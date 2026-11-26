#pragma once

#include <array>
#include <atomic>
#include <bit>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <span>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#include <boost/asio.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/lockfree/spsc_queue.hpp>

namespace net {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// ============================================================================
// 1. Byte Order & FrameCodec Sözleşmesi
// ============================================================================

inline constexpr std::uint32_t ToHost32(std::uint32_t v) noexcept {
  return (std::endian::native == std::endian::little) ? std::byteswap(v) : v;
}

inline constexpr std::uint32_t ToNet32(std::uint32_t v) noexcept {
  return ToHost32(v);
}

struct NoMeta {};

struct MsgIdMeta {
  std::uint32_t msg_id = 0;
};

template <typename Meta>
struct DecodedHeader {
  Meta meta{};
  std::uint32_t payload_len = 0;
};

template <typename C>
concept FrameCodec = requires(
    std::span<const std::byte, C::kHeaderSize> in_hdr,
    std::span<std::byte, C::kHeaderSize> out_hdr,
    const typename C::Meta& meta, std::uint32_t payload_len) {
  typename C::Meta;
  { C::kHeaderSize } -> std::convertible_to<std::size_t>;
  { C::DecodeHeader(in_hdr) } -> std::same_as<DecodedHeader<typename C::Meta>>;
  { C::EncodeHeader(out_hdr, meta, payload_len) } -> std::same_as<void>;
};

// Format 1: [4B len (BE)] + [proto]
struct LengthCodec {
  using Meta = NoMeta;
  static constexpr std::size_t kHeaderSize = sizeof(std::uint32_t);

  static DecodedHeader<Meta> DecodeHeader(
      std::span<const std::byte, kHeaderSize> hdr) noexcept {
    std::uint32_t net_len = 0;
    std::memcpy(&net_len, hdr.data(), sizeof(net_len));
    return DecodedHeader<Meta>{.meta = {}, .payload_len = ToHost32(net_len)};
  }

  static void EncodeHeader(std::span<std::byte, kHeaderSize> out, const Meta&,
                           std::uint32_t payload_len) noexcept {
    const std::uint32_t net_len = ToNet32(payload_len);
    std::memcpy(out.data(), &net_len, sizeof(net_len));
  }
};

// Format 2: [4B msg_id (BE)] + [4B len (BE)] + [proto]
struct MsgIdLengthCodec {
  using Meta = MsgIdMeta;
  static constexpr std::size_t kHeaderSize = 2 * sizeof(std::uint32_t);

  static DecodedHeader<Meta> DecodeHeader(
      std::span<const std::byte, kHeaderSize> hdr) noexcept {
    std::uint32_t net_id = 0;
    std::uint32_t net_len = 0;
    std::memcpy(&net_id, hdr.data(), sizeof(net_id));
    std::memcpy(&net_len, hdr.data() + sizeof(net_id), sizeof(net_len));
    return DecodedHeader<Meta>{
        .meta = MsgIdMeta{.msg_id = ToHost32(net_id)},
        .payload_len = ToHost32(net_len),
    };
  }

  static void EncodeHeader(std::span<std::byte, kHeaderSize> out,
                           const Meta& meta,
                           std::uint32_t payload_len) noexcept {
    const std::uint32_t net_id = ToNet32(meta.msg_id);
    const std::uint32_t net_len = ToNet32(payload_len);
    std::memcpy(out.data(), &net_id, sizeof(net_id));
    std::memcpy(out.data() + sizeof(net_id), &net_len, sizeof(net_len));
  }
};

// ============================================================================
// 2. Sunucu Konfigürasyonu & Session<Codec>
// ============================================================================

struct ServerConfig {
  std::uint16_t port = 9000;
  std::size_t worker_threads = 4;       // 0 = inline (unit test), >0 = sharded SPSC
  std::uint32_t max_frame_size = 64 * 1024;
  std::size_t read_buf_capacity = 128 * 1024;
  std::size_t queue_capacity = 16384;   // Worker başına boost::lockfree::spsc_queue kapasitesi
};

template <FrameCodec Codec>
class TcpServer;

template <FrameCodec Codec>
class Session : public std::enable_shared_from_this<Session<Codec>> {
 public:
  using Meta = typename Codec::Meta;

  std::uint64_t Id() const noexcept { return id_; }

  // LengthCodec kullanan servisler için: session->Send(reply_proto)
  template <typename OutProto>
    requires std::same_as<Meta, NoMeta>
  void Send(const OutProto& msg) {
    SendWithMeta(NoMeta{}, msg);
  }

  // MsgIdLengthCodec kullanan servisler için: session->Send(msg_id, reply_proto)
  template <typename OutProto>
    requires std::same_as<Meta, MsgIdMeta>
  void Send(std::uint32_t msg_id, const OutProto& msg) {
    SendWithMeta(MsgIdMeta{.msg_id = msg_id}, msg);
  }

  // Herhangi bir özel Codec için genel metot
  template <typename OutProto>
  void SendWithMeta(const Meta& meta, const OutProto& msg) {
    const std::uint32_t payload_len =
        static_cast<std::uint32_t>(msg.ByteSizeLong());
    std::vector<std::byte> frame(Codec::kHeaderSize + payload_len);

    Codec::EncodeHeader(
        std::span<std::byte, Codec::kHeaderSize>{frame.data(),
                                                 Codec::kHeaderSize},
        meta, payload_len);

    if (payload_len > 0) {
      msg.SerializeToArray(frame.data() + Codec::kHeaderSize,
                           static_cast<int>(payload_len));
    }

    SendRaw(std::move(frame));
  }

  // Thread-safe: herhangi bir worker thread'inden çağrılabilir
  void SendRaw(std::vector<std::byte> frame) {
    auto self = this->shared_from_this();
    asio::post(socket_.get_executor(),
               [self = std::move(self), f = std::move(frame)]() mutable {
                 if (self->force_closed_) return;
                 const bool write_idle = self->write_queue_.empty();
                 self->write_queue_.push_back(std::move(f));
                 if (write_idle) {
                   self->DoWrite();
                 }
               });
  }

  // Bekleyen yazmaları gönderip bağlantıyı temizce kapatır (thread-safe)
  void Close() {
    auto self = this->shared_from_this();
    asio::post(socket_.get_executor(),
               [self = std::move(self)]() { self->GracefulCloseOnIo(); });
  }

 private:
  friend class TcpServer<Codec>;

  Session(std::uint64_t id, tcp::socket socket, std::uint32_t max_frame_size,
          std::size_t read_buf_capacity)
      : id_(id),
        socket_(std::move(socket)),
        max_frame_size_(max_frame_size),
        read_buf_(read_buf_capacity) {}

  template <typename OnFrameFn, typename OnDisconnectFn>
  void StartRead(OnFrameFn&& on_frame, OnDisconnectFn&& on_disconnect) {
    auto self = this->shared_from_this();
    asio::co_spawn(
        socket_.get_executor(),
        [self = std::move(self), on_frame = std::forward<OnFrameFn>(on_frame),
         on_disconnect = std::forward<OnDisconnectFn>(
             on_disconnect)]() mutable -> asio::awaitable<void> {
          co_await self->ReadLoop(on_frame);
          on_disconnect(self);
        },
        asio::detached);
  }

  template <typename OnFrameFn>
  asio::awaitable<void> ReadLoop(OnFrameFn& on_frame) {
    constexpr std::size_t kHeaderSize = Codec::kHeaderSize;
    const std::size_t capacity = read_buf_.size();
    std::size_t read_pos = 0;
    std::size_t write_pos = 0;

    try {
      for (;;) {
        if (capacity - write_pos < 4096) {
          const std::size_t remaining = write_pos - read_pos;
          if (remaining > 0 && read_pos > 0) {
            std::memmove(read_buf_.data(), read_buf_.data() + read_pos,
                         remaining);
          }
          read_pos = 0;
          write_pos = remaining;
        }

        const std::size_t bytes_read = co_await socket_.async_read_some(
            asio::buffer(read_buf_.data() + write_pos, capacity - write_pos),
            asio::use_awaitable);
        write_pos += bytes_read;

        for (;;) {
          const std::size_t available = write_pos - read_pos;
          if (available < kHeaderSize) break;

          const auto hdr = Codec::DecodeHeader(
              std::span<const std::byte, kHeaderSize>{
                  read_buf_.data() + read_pos, kHeaderSize});
          const std::uint32_t payload_len = hdr.payload_len;

          if (payload_len == 0 || payload_len > max_frame_size_) [[unlikely]] {
            co_return;
          }
          if (available < kHeaderSize + payload_len) break;

          std::span<const std::byte> payload{
              read_buf_.data() + read_pos + kHeaderSize, payload_len};
          read_pos += kHeaderSize + payload_len;

          if (read_pos == write_pos) {
            read_pos = 0;
            write_pos = 0;
          }

          on_frame(this->shared_from_this(), hdr.meta, payload);
        }
      }
    } catch (const boost::system::system_error&) {
      // EOF, shutdown veya bağlantı koptu
    }
  }

  void DoWrite() {
    auto self = this->shared_from_this();
    const auto& front = write_queue_.front();
    asio::async_write(
        socket_, asio::buffer(front.data(), front.size()),
        [self = std::move(self)](const boost::system::error_code& ec,
                                 std::size_t) {
          if (ec) [[unlikely]] {
            self->write_queue_.clear();
            self->CloseSocketIgnoreErrors();
            return;
          }
          self->write_queue_.pop_front();
          if (!self->write_queue_.empty()) {
            self->DoWrite();
          } else if (self->close_after_write_) {
            self->CloseSocketIgnoreErrors();
          }
        });
  }

  // Yeni okuma durdurulur; worker'ların yollayacağı yanıtlar için yazma açık kalır
  void StopReadingOnIo() {
    boost::system::error_code ec;
    socket_.shutdown(tcp::socket::shutdown_receive, ec);
  }

  // Bekleyen yazmalar bitince soketi kapatır
  void GracefulCloseOnIo() {
    StopReadingOnIo();
    close_after_write_ = true;
    if (write_queue_.empty()) {
      CloseSocketIgnoreErrors();
    }
  }

  void ForceCloseOnIo() {
    force_closed_ = true;
    write_queue_.clear();
    CloseSocketIgnoreErrors();
  }

  void CloseSocketIgnoreErrors() {
    boost::system::error_code ec;
    if (socket_.is_open()) {
      socket_.shutdown(tcp::socket::shutdown_both, ec);
      socket_.close(ec);
    }
  }

  std::uint64_t id_;
  tcp::socket socket_;
  std::uint32_t max_frame_size_;
  std::vector<std::byte> read_buf_;
  std::deque<std::vector<std::byte>> write_queue_;
  bool close_after_write_ = false;
  bool force_closed_ = false;
};

// ============================================================================
// 3. Generic TcpServer<Codec> (Tek I/O Thread + Boost.Lockfree Sharded SPSC)
// ============================================================================

template <FrameCodec Codec = LengthCodec>
class TcpServer {
 public:
  using SessionType = Session<Codec>;
  using SessionPtr = std::shared_ptr<SessionType>;
  using Meta = typename Codec::Meta;

  using FrameCallback = std::conditional_t<
      std::same_as<Meta, NoMeta>,
      std::function<void(SessionPtr, std::span<const std::byte>)>,
      std::function<void(SessionPtr, Meta, std::span<const std::byte>)>>;

  using DisconnectCallback = std::function<void(SessionPtr)>;
  using DropCallback = std::function<void(SessionPtr, std::size_t)>;

  TcpServer(asio::io_context& io_ctx, ServerConfig cfg)
      : io_ctx_(io_ctx),
        cfg_(cfg),
        acceptor_(io_ctx) {
    if (cfg_.read_buf_capacity < cfg_.max_frame_size + Codec::kHeaderSize) {
      cfg_.read_buf_capacity = cfg_.max_frame_size + Codec::kHeaderSize;
    }
  }

  ~TcpServer() { ForceStop(); }

  TcpServer(const TcpServer&) = delete;
  TcpServer& operator=(const TcpServer&) = delete;

  void OnFrame(FrameCallback cb) { on_frame_ = std::move(cb); }
  void OnDisconnect(DisconnectCallback cb) { on_disconnect_ = std::move(cb); }
  void OnDrop(DropCallback cb) { on_drop_ = std::move(cb); }

  std::uint64_t DroppedCount() const noexcept {
    return dropped_count_.load(std::memory_order_relaxed);
  }

  // Ephemeral port (cfg.port == 0) kullanıldığında işletim sisteminin atadığı portu döner
  std::uint16_t Port() const {
    return acceptor_.is_open() ? acceptor_.local_endpoint().port() : cfg_.port;
  }

  void Start() {
    if (running_.exchange(true)) return;

    tcp::endpoint ep{tcp::v4(), cfg_.port};
    acceptor_.open(ep.protocol());
    acceptor_.set_option(tcp::acceptor::reuse_address(true));
    acceptor_.bind(ep);
    acceptor_.listen();

    // Sharded boost::lockfree::spsc_queue worker'larını başlat (0 ise inline mod)
    if (cfg_.worker_threads > 0) {
      workers_.reserve(cfg_.worker_threads);
      for (std::size_t i = 0; i < cfg_.worker_threads; ++i) {
        auto worker = std::make_unique<Worker>(cfg_.queue_capacity);
        worker->thread = std::jthread([this, w = worker.get()] { WorkerLoop(*w); });
        workers_.push_back(std::move(worker));
      }
    }

    asio::co_spawn(
        io_ctx_,
        [this]() -> asio::awaitable<void> { co_await AcceptLoop(); },
        asio::detached);
  }

  // Graceful Stop:
  // 1) Yeni bağlantıları ve okumaları keser
  // 2) Worker kuyruklarındaki bekleyen işleri bitirir (cevaplar Send() ile post edilir)
  // 3) Bekleyen yazmalar bitince tüm soketleri temizce kapatır
  void Stop() {
    if (!running_.exchange(false)) return;

    asio::post(io_ctx_, [this] {
      boost::system::error_code ec;
      acceptor_.close(ec);
      for (auto& [id, weak] : sessions_) {
        if (auto s = weak.lock()) {
          s->StopReadingOnIo();
        }
      }
    });

    StopWorkers(/*drain=*/true);

    asio::post(io_ctx_, [this] {
      for (auto& [id, weak] : sessions_) {
        if (auto s = weak.lock()) {
          s->GracefulCloseOnIo();
        }
      }
    });
  }

  // Acil Stop: Kuyrukları ve yazmaları beklemeden anında durdurur
  void ForceStop() {
    const bool was_running = running_.exchange(false);
    if (!was_running && workers_.empty()) return;

    StopWorkers(/*drain=*/false);

    asio::post(io_ctx_, [this] {
      boost::system::error_code ec;
      if (acceptor_.is_open()) acceptor_.close(ec);
      for (auto& [id, weak] : sessions_) {
        if (auto s = weak.lock()) {
          s->ForceCloseOnIo();
        }
      }
      sessions_.clear();
    });
  }

 private:
  struct WorkItem {
    SessionPtr session;
    Meta meta{};
    std::vector<std::byte> payload;
  };

  struct Worker {
    explicit Worker(std::size_t cap) : queue(cap) {}

    bool TryPush(WorkItem&& item) {
      if (!queue.push(std::move(item))) [[unlikely]] {
        return false;
      }
      std::atomic_thread_fence(std::memory_order_seq_cst);
      if (sleeping.load(std::memory_order_relaxed)) {
        wake_seq.fetch_add(1, std::memory_order_release);
        wake_seq.notify_one();
      }
      return true;
    }

    bool WaitAndPop(WorkItem& out) {
      for (;;) {
        for (int spin = 0; spin < 64; ++spin) {
          if (queue.pop(out)) return true;
          if (stop_immediate.load(std::memory_order_acquire)) return false;
        }

        const std::uint64_t seq = wake_seq.load(std::memory_order_acquire);
        sleeping.store(true, std::memory_order_seq_cst);

        if (queue.pop(out)) {
          sleeping.store(false, std::memory_order_relaxed);
          return true;
        }
        if (stop_immediate.load(std::memory_order_acquire) ||
            stop_drain.load(std::memory_order_acquire)) {
          sleeping.store(false, std::memory_order_relaxed);
          return false;
        }

        wake_seq.wait(seq, std::memory_order_acquire);
        sleeping.store(false, std::memory_order_relaxed);
      }
    }

    void RequestStop(bool drain) {
      if (drain) {
        stop_drain.store(true, std::memory_order_seq_cst);
      } else {
        stop_immediate.store(true, std::memory_order_seq_cst);
      }
      wake_seq.fetch_add(1, std::memory_order_release);
      wake_seq.notify_all();
    }

    boost::lockfree::spsc_queue<WorkItem> queue;
    std::atomic<bool> sleeping{false};
    std::atomic<std::uint64_t> wake_seq{0};
    std::atomic<bool> stop_drain{false};
    std::atomic<bool> stop_immediate{false};
    std::jthread thread;
  };

  asio::awaitable<void> AcceptLoop() {
    try {
      for (;;) {
        tcp::socket socket{io_ctx_};
        co_await acceptor_.async_accept(socket, asio::use_awaitable);

        boost::system::error_code ec;
        socket.set_option(tcp::no_delay(true), ec);

        const std::uint64_t id = ++next_session_id_;
        auto session = std::shared_ptr<SessionType>(
            new SessionType(id, std::move(socket), cfg_.max_frame_size,
                            cfg_.read_buf_capacity));

        sessions_.emplace(id, session);

        session->StartRead(
            [this](SessionPtr s, const Meta& meta,
                   std::span<const std::byte> payload) {
              DispatchFrame(std::move(s), meta, payload);
            },
            [this](SessionPtr s) {
              sessions_.erase(s->Id());
              if (on_disconnect_) {
                on_disconnect_(std::move(s));
              }
            });
      }
    } catch (const boost::system::system_error&) {
      // Acceptor kapatıldı (Stop / ForceStop)
    }
  }

  void DispatchFrame(SessionPtr session, const Meta& meta,
                     std::span<const std::byte> payload) {
    if (!on_frame_) return;

    // Inline mod (unit testler için worker_threads == 0)
    if (workers_.empty()) {
      InvokeOnFrame(std::move(session), meta, payload);
      return;
    }

    // Aynı TCP bağlantısı hep aynı worker'a gider (FIFO sıra garantisi)
    const std::size_t idx = session->Id() % workers_.size();
    WorkItem item{
        .session = session,
        .meta = meta,
        .payload = std::vector<std::byte>(payload.begin(), payload.end()),
    };

    // Non-blocking push: kuyruk dolarsa I/O thread asla bloklanmaz
    if (!workers_[idx]->TryPush(std::move(item))) [[unlikely]] {
      dropped_count_.fetch_add(1, std::memory_order_relaxed);
      if (on_drop_) {
        on_drop_(std::move(session), payload.size());
      }
    }
  }

  void WorkerLoop(Worker& worker) {
    WorkItem item;
    while (worker.WaitAndPop(item)) {
      InvokeOnFrame(std::move(item.session), item.meta, item.payload);
      item.session.reset();
    }
  }

  void InvokeOnFrame(SessionPtr session, const Meta& meta,
                     std::span<const std::byte> payload) {
    if constexpr (std::same_as<Meta, NoMeta>) {
      on_frame_(std::move(session), payload);
    } else {
      on_frame_(std::move(session), meta, payload);
    }
  }

  void StopWorkers(bool drain) {
    for (auto& w : workers_) {
      w->RequestStop(drain);
    }
    workers_.clear();  // std::jthread yıkıcıları tüm worker'ları join eder
  }

  asio::io_context& io_ctx_;
  ServerConfig cfg_;
  tcp::acceptor acceptor_;

  FrameCallback on_frame_;
  DisconnectCallback on_disconnect_;
  DropCallback on_drop_;

  std::uint64_t next_session_id_ = 0;
  std::unordered_map<std::uint64_t, std::weak_ptr<SessionType>> sessions_;

  std::vector<std::unique_ptr<Worker>> workers_;
  std::atomic<bool> running_{false};
  std::atomic<std::uint64_t> dropped_count_{0};
};

}  // namespace net
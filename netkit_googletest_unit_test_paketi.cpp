#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <expected>
#include <functional>
#include <limits>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <variant>
#include <vector>

#include <boost/asio.hpp>

#include "netkit/proto_parser.hpp"
#include "netkit/tcp_server.hpp"

namespace {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// ============================================================================
// 1. Test Yardımcıları ve Sahte (Fake) Protobuf Mesajları
// ============================================================================

struct FakeItem {
  const std::string& sku() const { return sku_; }
  double price() const { return price_; }
  std::string sku_;
  double price_ = 0.0;
};

struct FakeAddress {
  const std::string& city() const { return city_; }
  std::string city_;
};

struct FakeCard {
  const std::string& last4() const { return last4_; }
  std::string last4_;
};

struct FakeOrder {
  enum PaymentCase { PAYMENT_NOT_SET = 0, kCard = 1 };

  // Test kolaylığı: ham byte'lar "BAD" ise parse hatası simüle eder,
  // aksi halde sabit geçerli/test edilebilir alanlarla doldurur.
  bool ParseFromArray(const void* data, int size) {
    if (size == 3 && std::memcmp(data, "BAD", 3) == 0) return false;
    if (size == 4 && std::memcmp(data, "ZERO", 4) == 0) {
      id_ = 0;  // Validasyon hatasını tetikler
      return true;
    }
    id_ = 42;
    score_ = 10.0;
    has_addr_ = true;
    addr_.city_ = "Ankara";
    items_ = {FakeItem{.sku_ = "SKU-1", .price_ = 50.0}};
    payment_case_ = kCard;
    card_.last4_ = "1234";
    start_time_ = 100;
    end_time_ = 200;
    return true;
  }

  std::size_t ByteSizeLong() const { return raw_payload_.size(); }
  bool SerializeToArray(void* out, int size) const {
    if (size > 0) std::memcpy(out, raw_payload_.data(), static_cast<std::size_t>(size));
    return true;
  }

  std::uint64_t id() const { return id_; }
  double score() const { return score_; }
  bool has_addr() const { return has_addr_; }
  const FakeAddress& addr() const { return addr_; }
  bool has_coupon() const { return has_coupon_; }
  const std::string& coupon() const { return coupon_; }
  const std::vector<FakeItem>& items() const { return items_; }
  PaymentCase payment_case() const { return payment_case_; }
  const FakeCard& card() const { return card_; }
  std::int64_t start_time() const { return start_time_; }
  std::int64_t end_time() const { return end_time_; }

  std::uint64_t id_ = 1;
  double score_ = 0.0;
  bool has_addr_ = true;
  FakeAddress addr_{.city_ = "Ankara"};
  bool has_coupon_ = false;
  std::string coupon_;
  std::vector<FakeItem> items_{FakeItem{.sku_ = "A1", .price_ = 10.0}};
  PaymentCase payment_case_ = kCard;
  FakeCard card_{.last4_ = "4242"};
  std::int64_t start_time_ = 10;
  std::int64_t end_time_ = 20;
  std::string raw_payload_;
};

// Basit Echo / Wire mesajı (TcpServer testleri için)
struct WireBlob {
  std::string data;
  std::size_t ByteSizeLong() const { return data.size(); }
  bool SerializeToArray(void* out, int size) const {
    if (size > 0) std::memcpy(out, data.data(), static_cast<std::size_t>(size));
    return true;
  }
};

using namespace proto;

inline constexpr Spec kAddrSpec{
    Rule<&FakeAddress::city>("city", NotEmpty{}),
};

inline constexpr Spec kItemSpec{
    Rule<&FakeItem::sku>("sku", NotEmpty{}),
    Rule<&FakeItem::price>("price", Between<double>{0.01, 10'000.0}),
};

inline constexpr Spec kCardSpec{
    Rule<&FakeCard::last4>("last4", NotEmpty{}),
};

inline constexpr Spec kOrderSpec{
    Rule<&FakeOrder::id>("id", Between<std::uint64_t>{1, 1'000'000}),
    Rule<&FakeOrder::score>("score", Between<double>{-100.0, 100.0}),
    Required<&FakeOrder::has_addr, &FakeOrder::addr>("addr", Nested<kAddrSpec>{}),
    Optional<&FakeOrder::has_coupon, &FakeOrder::coupon>("coupon", NotEmpty{}),
    Rule<[](const FakeOrder& o) -> const auto& { return o.items(); }>(
        "items", SizeBetween{1, 10}, Each<kItemSpec>{}),
    OneOf<&FakeOrder::payment_case, /*IsRequired=*/true>(
        "payment", OneOfCase<FakeOrder::kCard, &FakeOrder::card, kCardSpec>{}),
    CrossField("end_time", "must be greater than start_time",
               [](const FakeOrder& o) { return o.end_time() > o.start_time(); }),
};

// Ham string -> std::span<const std::byte> yardımcısı
std::vector<std::byte> ToBytes(std::string_view sv) {
  std::vector<std::byte> out(sv.size());
  if (!sv.empty()) std::memcpy(out.data(), sv.data(), sv.size());
  return out;
}

std::string FromBytes(std::span<const std::byte> s) {
  return std::string(reinterpret_cast<const char*>(s.data()), s.size());
}

// Codec'e göre tek frame paketleyen genel yardımcı
template <net::FrameCodec Codec>
std::vector<std::byte> EncodeFrame(const typename Codec::Meta& meta,
                                   std::string_view payload) {
  std::vector<std::byte> buf(Codec::kHeaderSize + payload.size());
  Codec::EncodeHeader(
      std::span<std::byte, Codec::kHeaderSize>{buf.data(), Codec::kHeaderSize},
      meta, static_cast<std::uint32_t>(payload.size()));
  if (!payload.empty()) {
    std::memcpy(buf.data() + Codec::kHeaderSize, payload.data(), payload.size());
  }
  return buf;
}

// ============================================================================
// 2. Value-Parameterized Testler: NaN/Inf Güvenli Between & BetweenApprox
// ============================================================================

struct DoubleRangeCase {
  std::string name;
  double value;
  bool expected_ok;
};

class BetweenDoubleTest : public ::testing::TestWithParam<DoubleRangeCase> {};

TEST_P(BetweenDoubleTest, EvaluatesRangeAndSpecialFloats) {
  const auto& tc = GetParam();
  constexpr Between<double> rule{-10.0, 10.0};
  ValidationError err;

  EXPECT_EQ(rule("v", tc.value, err), tc.expected_ok);
  if (!tc.expected_ok) {
    EXPECT_EQ(err.FormatPath(), "v");
    EXPECT_EQ(err.reason, "out of range");
  }
}

INSTANTIATE_TEST_SUITE_P(
    RangeEdgeCases, BetweenDoubleTest,
    ::testing::Values(
        DoubleRangeCase{"Inside", 0.0, true},
        DoubleRangeCase{"MinBoundary", -10.0, true},
        DoubleRangeCase{"MaxBoundary", 10.0, true},
        DoubleRangeCase{"BelowMin", -10.0001, false},
        DoubleRangeCase{"AboveMax", 10.0001, false},
        DoubleRangeCase{"QuietNaN", std::numeric_limits<double>::quiet_NaN(), false},
        DoubleRangeCase{"PosInf", std::numeric_limits<double>::infinity(), false},
        DoubleRangeCase{"NegInf", -std::numeric_limits<double>::infinity(), false}),
    [](const auto& info) { return info.param.name; });

TEST(BetweenApproxTest, AcceptsWithinEpsilonAndRejectsNaN) {
  constexpr BetweenApprox<double> rule{-90.0, 90.0, 1e-6};
  ValidationError err;
  EXPECT_TRUE(rule("lat", 90.0 + 5e-7, err));
  EXPECT_FALSE(rule("lat", 90.0 + 2e-6, err));
  EXPECT_FALSE(rule("lat", std::numeric_limits<double>::quiet_NaN(), err));
}

// ============================================================================
// 3. Value-Parameterized Testler: Spec Validasyon & Unwinding FieldPath
// ============================================================================

struct ValidationCase {
  std::string name;
  std::function<void(FakeOrder&)> mutate;
  bool expected_ok;
  std::string expected_path;
  std::string expected_reason;
};

class OrderSpecValidationTest : public ::testing::TestWithParam<ValidationCase> {};

TEST_P(OrderSpecValidationTest, ValidatesAndUnwindsPath) {
  const auto& tc = GetParam();
  FakeOrder order;  // Varsayılan olarak tüm kurallardan geçen geçerli sipariş
  tc.mutate(order);

  auto res = kOrderSpec.Validate(order);
  ASSERT_EQ(res.has_value(), tc.expected_ok);

  if (!tc.expected_ok) {
    EXPECT_EQ(res.error().FormatPath(), tc.expected_path);
    EXPECT_EQ(res.error().reason, tc.expected_reason);
  }
}

INSTANTIATE_TEST_SUITE_P(
    SpecRules, OrderSpecValidationTest,
    ::testing::Values(
        ValidationCase{"ValidDefault", [](FakeOrder&) {}, true, "", ""},
        ValidationCase{"OptionalCouponValid",
                       [](FakeOrder& o) {
                         o.has_coupon_ = true;
                         o.coupon_ = "SAVE10";
                       },
                       true, "", ""},
        ValidationCase{"OptionalCouponEmptyFails",
                       [](FakeOrder& o) {
                         o.has_coupon_ = true;
                         o.coupon_.clear();
                       },
                       false, "coupon", "must not be empty"},
        ValidationCase{"RequiredAddrMissing",
                       [](FakeOrder& o) { o.has_addr_ = false; }, false, "addr",
                       "required field missing"},
        ValidationCase{"NestedAddrCityEmpty",
                       [](FakeOrder& o) { o.addr_.city_.clear(); }, false,
                       "addr.city", "must not be empty"},
        ValidationCase{"RepeatedEmptyFails",
                       [](FakeOrder& o) { o.items_.clear(); }, false, "items",
                       "invalid item count"},
        ValidationCase{"RepeatedSecondItemPriceInvalid",
                       [](FakeOrder& o) {
                         o.items_.push_back(FakeItem{.sku_ = "B2", .price_ = -5.0});
                       },
                       false, "items[1].price", "out of range"},
        ValidationCase{"OneOfMissingFails",
                       [](FakeOrder& o) {
                         o.payment_case_ = FakeOrder::PAYMENT_NOT_SET;
                       },
                       false, "payment", "oneof must be set"},
        ValidationCase{"OneOfNestedCardEmptyFails",
                       [](FakeOrder& o) { o.card_.last4_.clear(); }, false,
                       "payment.last4", "must not be empty"},
        ValidationCase{"CrossFieldTimeRangeFails",
                       [](FakeOrder& o) {
                         o.start_time_ = 500;
                         o.end_time_ = 400;
                       },
                       false, "end_time", "must be greater than start_time"}),
    [](const auto& info) { return info.param.name; });

// ============================================================================
// 4. Fixture Test: ProtoParser (Parse -> Validate -> Map & Arena Yeniden Kullanımı)
// ============================================================================

class ProtoParserTest : public ::testing::Test {
 protected:
  ProtoParser parser_;
};

TEST_F(ProtoParserTest, ReturnsParseErrorOnCorruptBytes) {
  auto res = parser_.Parse<FakeOrder, kOrderSpec>(
      ToBytes("BAD"), [](const FakeOrder& o) { return o.id(); });
  ASSERT_FALSE(res.has_value());
  EXPECT_TRUE(std::holds_alternative<ParseError>(res.error()));
}

TEST_F(ProtoParserTest, ReturnsValidationErrorWhenSpecFails) {
  auto res = parser_.Parse<FakeOrder, kOrderSpec>(
      ToBytes("ZERO"), [](const FakeOrder& o) { return o.id(); });
  ASSERT_FALSE(res.has_value());
  ASSERT_TRUE(std::holds_alternative<ValidationError>(res.error()));
  EXPECT_EQ(std::get<ValidationError>(res.error()).FormatPath(), "id");
}

TEST_F(ProtoParserTest, SupportsFallibleMapperReturningExpected) {
  auto res = parser_.Parse<FakeOrder, kOrderSpec>(
      ToBytes("OK"),
      [](const FakeOrder&) -> std::expected<int, MappingError> {
        return std::unexpected(MappingError{"unknown currency"});
      });
  ASSERT_FALSE(res.has_value());
  ASSERT_TRUE(std::holds_alternative<MappingError>(res.error()));
  EXPECT_EQ(std::get<MappingError>(res.error()).reason, "unknown currency");
}

TEST_F(ProtoParserTest, ReusesArenaAcrossRepeatedSuccessfulCalls) {
  for (int i = 0; i < 100; ++i) {
    auto res = parser_.Parse<FakeOrder, kOrderSpec>(
        ToBytes("OK"), [](const FakeOrder& o) { return o.id(); });
    ASSERT_TRUE(res.has_value());
    EXPECT_EQ(*res, 42u);
  }
}

// ============================================================================
// 5. Typed Testler: LengthCodec & MsgIdLengthCodec (Tek Test, İki Codec)
// ============================================================================

template <typename Codec>
class CodecTypedTest : public ::testing::Test {};

using TestedCodecs = ::testing::Types<net::LengthCodec, net::MsgIdLengthCodec>;
TYPED_TEST_SUITE(CodecTypedTest, TestedCodecs);

TYPED_TEST(CodecTypedTest, HeaderEncodeDecodeRoundTrip) {
  using Codec = TypeParam;
  typename Codec::Meta meta{};
  if constexpr (std::same_as<typename Codec::Meta, net::MsgIdMeta>) {
    meta.msg_id = 0x1234ABCD;
  }

  std::array<std::byte, Codec::kHeaderSize> wire{};
  Codec::EncodeHeader(wire, meta, 65'432);
  auto decoded = Codec::DecodeHeader(wire);

  EXPECT_EQ(decoded.payload_len, 65'432u);
  if constexpr (std::same_as<typename Codec::Meta, net::MsgIdMeta>) {
    EXPECT_EQ(decoded.meta.msg_id, 0x1234ABCDu);
  }
}

// ============================================================================
// 6. Lock-Free SpscQueue Testleri
// ============================================================================

TEST(SpscQueueTest, PreservesFifoAndRejectsWhenFull) {
  // Kapasite 4 (1 slot ring-buffer doluluk ayrımı için kullanılır -> max 3 öğe)
  net::detail::SpscQueue<int> q(4);
  EXPECT_TRUE(q.TryPush(10));
  EXPECT_TRUE(q.TryPush(20));
  EXPECT_TRUE(q.TryPush(30));
  EXPECT_FALSE(q.TryPush(40));  // Kuyruk dolu: non-blocking false

  int v = 0;
  ASSERT_TRUE(q.TryPop(v));
  EXPECT_EQ(v, 10);
  ASSERT_TRUE(q.TryPop(v));
  EXPECT_EQ(v, 20);
  ASSERT_TRUE(q.TryPop(v));
  EXPECT_EQ(v, 30);
  EXPECT_FALSE(q.TryPop(v));
}

TEST(SpscQueueTest, ProducerConsumerDrainsAllItemsOnGracefulStop) {
  constexpr int kCount = 20'000;
  net::detail::SpscQueue<int> q(1024);
  std::vector<int> received;
  received.reserve(kCount);

  std::jthread consumer([&] {
    int item = 0;
    while (q.WaitAndPop(item)) {
      received.push_back(item);
    }
  });

  for (int i = 0; i < kCount; ++i) {
    while (!q.TryPush(int{i})) {
      std::this_thread::yield();
    }
  }
  q.RequestStop(/*drain=*/true);
  consumer.join();

  ASSERT_EQ(received.size(), static_cast<std::size_t>(kCount));
  for (int i = 0; i < kCount; ++i) {
    EXPECT_EQ(received[i], i);
  }
}

// ============================================================================
// 7. Value-Parameterized Entegrasyon Testleri: TcpServer (Inline vs Worker Modu)
// ============================================================================

class TcpServerModeTest : public ::testing::TestWithParam<std::size_t> {
 protected:
  // Tek bir yardımcı: sunucuyu arka plan io_context thread'inde başlatır,
  // client ile iletişim bittikten sonra temizce durdurur.
  template <net::FrameCodec Codec>
  struct Harness {
    asio::io_context io_ctx;
    net::TcpServer<Codec> server;
    std::jthread io_thread;

    explicit Harness(std::size_t worker_threads)
        : server(io_ctx, net::ServerConfig{
                             .port = 0,  // OS boş port atar
                             .worker_threads = worker_threads,
                             .max_frame_size = 4096,
                             .queue_capacity = 256,
                         }) {}

    void Start() {
      server.Start();
      io_thread = std::jthread([this] { io_ctx.run(); });
    }

    void Stop() {
      server.Stop();
      if (io_thread.joinable()) io_thread.join();
    }

    ~Harness() {
      server.ForceStop();
      io_ctx.stop();
    }
  };

  static tcp::socket ConnectClient(asio::io_context& client_io,
                                   std::uint16_t port) {
    tcp::socket sock(client_io);
    sock.connect(tcp::endpoint{asio::ip::make_address("127.0.0.1"), port});
    return sock;
  }

  template <net::FrameCodec Codec>
  static std::pair<typename Codec::Meta, std::string> ReadFrame(
      tcp::socket& sock) {
    std::array<std::byte, Codec::kHeaderSize> hdr_buf{};
    asio::read(sock, asio::buffer(hdr_buf));
    auto hdr = Codec::DecodeHeader(hdr_buf);

    std::string body(hdr.payload_len, '\0');
    if (hdr.payload_len > 0) {
      asio::read(sock, asio::buffer(body));
    }
    return {hdr.meta, std::move(body)};
  }
};

TEST_P(TcpServerModeTest, HandlesCoalescedAndFragmentedLengthFramesAndReplies) {
  Harness<net::LengthCodec> h(GetParam());

  h.server.OnFrame([](auto session, std::span<const std::byte> payload) {
    session->Send(WireBlob{"ECHO:" + FromBytes(payload)});
  });
  h.Start();

  asio::io_context client_io;
  auto sock = ConnectClient(client_io, h.server.Port());

  // 1) Coalesced: iki frame tek write ile bitişik gönderilir
  auto f1 = EncodeFrame<net::LengthCodec>({}, "hello");
  auto f2 = EncodeFrame<net::LengthCodec>({}, "world");
  f1.insert(f1.end(), f2.begin(), f2.end());
  asio::write(sock, asio::buffer(f1));

  // 2) Fragmented: tek frame 2 byte'lık parçalar halinde gönderilir
  auto f3 = EncodeFrame<net::LengthCodec>({}, "fragmented_payload");
  for (std::size_t i = 0; i < f3.size(); i += 2) {
    const std::size_t n = std::min<std::size_t>(2, f3.size() - i);
    asio::write(sock, asio::buffer(f3.data() + i, n));
  }

  EXPECT_EQ(ReadFrame<net::LengthCodec>(sock).second, "ECHO:hello");
  EXPECT_EQ(ReadFrame<net::LengthCodec>(sock).second, "ECHO:world");
  EXPECT_EQ(ReadFrame<net::LengthCodec>(sock).second, "ECHO:fragmented_payload");

  sock.close();
  h.Stop();
}

TEST_P(TcpServerModeTest, RoutesMsgIdLengthCodecAndPreservesFifoOrder) {
  Harness<net::MsgIdLengthCodec> h(GetParam());

  h.server.OnFrame([](auto session, net::MsgIdMeta meta,
                      std::span<const std::byte> payload) {
    session->Send(meta.msg_id + 1, WireBlob{FromBytes(payload)});
  });
  h.Start();

  asio::io_context client_io;
  auto sock = ConnectClient(client_io, h.server.Port());

  // Aynı bağlantıdan ardışık 20 paket: worker_threads > 0 olsa bile FIFO korunmalı
  for (std::uint32_t i = 0; i < 20; ++i) {
    auto frame = EncodeFrame<net::MsgIdLengthCodec>(
        net::MsgIdMeta{.msg_id = 1000 + i}, "msg_" + std::to_string(i));
    asio::write(sock, asio::buffer(frame));
  }

  for (std::uint32_t i = 0; i < 20; ++i) {
    auto [meta, body] = ReadFrame<net::MsgIdLengthCodec>(sock);
    EXPECT_EQ(meta.msg_id, 1001 + i);
    EXPECT_EQ(body, "msg_" + std::to_string(i));
  }

  sock.close();
  h.Stop();
}

INSTANTIATE_TEST_SUITE_P(
    InlineAndShardedWorkers, TcpServerModeTest,
    ::testing::Values(std::size_t{0}, std::size_t{2}),
    [](const auto& info) {
      return info.param == 0 ? "InlineMode" : "TwoWorkerThreads";
    });

}  // namespace
#include <cstdint>
#include <iostream>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

#include "netkit/proto_parser.hpp"
#include "netkit/tcp_server.hpp"

namespace {

void LogPipelineError(std::uint64_t session_id,
                      const proto::PipelineError& err) {
  std::visit(
      proto::Overloaded{
          [session_id](const proto::ParseError& e) {
            std::cerr << "[session=" << session_id << "][PARSE] " << e.reason
                      << '\n';
          },
          [session_id](const proto::ValidationError& e) {
            std::cerr << "[session=" << session_id << "][VALIDATE] "
                      << e.FormatPath() << ": " << e.reason << '\n';
          },
          [session_id](const proto::MappingError& e) {
            std::cerr << "[session=" << session_id << "][MAP] " << e.reason
                      << '\n';
          },
      },
      err);
}

}  // namespace

// ============================================================================
// REPO 1 (Servis A): [4B len] + [proto] — oneof payload zarfı
// ============================================================================
namespace repo1 {

// --- protoc tarafından üretilen temsili mesajlar ---
struct V2Message {
  std::int32_t id() const { return id_; }
  const std::string& name() const { return name_; }
  std::int32_t id_ = 0;
  std::string name_;
};

struct Global1Message {
  double v1() const { return v1_; }
  bool has_v2() const { return has_v2_; }
  const V2Message& v2() const { return v2_; }
  const std::vector<V2Message>& v2_list() const { return v2_list_; }
  const V2Message& v2_list(int i) const { return v2_list_[i]; }

  double v1_ = 0.0;
  bool has_v2_ = false;
  V2Message v2_;
  std::vector<V2Message> v2_list_;
};

struct GlobalMessage {
  bool has_global1_message() const { return has_g1_; }
  const Global1Message& global1_message() const { return g1_; }
  bool has_g1_ = false;
  Global1Message g1_;
};

struct InputMessage {
  std::uint64_t seq() const { return seq_; }
  std::uint64_t seq_ = 0;
};

struct OutputMessage {
  std::int32_t code() const { return code_; }
  std::int32_t code_ = 0;
};

struct Message {
  enum PayloadCase {
    PAYLOAD_NOT_SET = 0,
    kGlobalMessage = 1,
    kInputMessage = 2,
    kOutputMessage = 3,
  };

  bool ParseFromArray(const void*, int) { return true; }
  std::size_t ByteSizeLong() const { return 16; }
  bool SerializeToArray(void*, int) const { return true; }

  PayloadCase payload_case() const { return case_; }
  const GlobalMessage& global_message() const { return global_; }
  const InputMessage& input_message() const { return input_; }
  const OutputMessage& output_message() const { return output_; }

  PayloadCase case_ = PAYLOAD_NOT_SET;
  GlobalMessage global_;
  InputMessage input_;
  OutputMessage output_;
};

// --- Spec tanımları (Bottom-Up) ---
using namespace proto;

inline constexpr Spec kV2Spec{
    Rule<&V2Message::id>("id", Between<std::int32_t>{1, 10'000}),
    Rule<&V2Message::name>("name", NotEmpty{}),
};

inline constexpr Spec kGlobal1Spec{
    Rule<&Global1Message::v1>("v1", Between<double>{-180.0, 180.0}),
    Required<&Global1Message::has_v2, &Global1Message::v2>(
        "v2", Nested<kV2Spec>{}),
    Rule<[](const Global1Message& m) -> const auto& { return m.v2_list(); }>(
        "v2_list", SizeBetween{1, 64}, Each<kV2Spec>{}),
};

inline constexpr Spec kGlobalSpec{
    Required<&GlobalMessage::has_global1_message,
             &GlobalMessage::global1_message>("global1_message",
                                              Nested<kGlobal1Spec>{}),
};

inline constexpr Spec kInputSpec{
    Rule<&InputMessage::seq>("seq", Between<std::uint64_t>{1, UINT64_MAX}),
};

inline constexpr Spec kOutputSpec{
    Rule<&OutputMessage::code>("code", Between<std::int32_t>{0, 999}),
};

inline constexpr Spec kMessageSpec{
    OneOf<&Message::payload_case, /*IsRequired=*/true>(
        "payload",
        OneOfCase<Message::kGlobalMessage, &Message::global_message,
                  kGlobalSpec>{},
        OneOfCase<Message::kInputMessage, &Message::input_message,
                  kInputSpec>{},
        OneOfCase<Message::kOutputMessage, &Message::output_message,
                  kOutputSpec>{}),
};

// --- Domain & Non-static Mapper ---
struct GlobalDomain {
  double v1 = 0.0;
  std::int32_t v2_id = 0;
  std::vector<std::int32_t> item_ids;
};
struct InputDomain {
  std::uint64_t seq = 0;
};
struct OutputDomain {
  std::int32_t code = 0;
};

using DomainMessage = std::variant<GlobalDomain, InputDomain, OutputDomain>;

class MessageMapper {
 public:
  DomainMessage Map(const Message& p) const {
    switch (p.payload_case()) {
      case Message::kGlobalMessage: {
        const auto& g1 = p.global_message().global1_message();
        GlobalDomain d{.v1 = g1.v1(), .v2_id = g1.v2().id(), .item_ids = {}};
        d.item_ids.reserve(g1.v2_list().size());
        for (const auto& item : g1.v2_list()) {
          d.item_ids.push_back(item.id());
        }
        return d;
      }
      case Message::kInputMessage:
        return InputDomain{.seq = p.input_message().seq()};
      case Message::kOutputMessage:
        return OutputDomain{.code = p.output_message().code()};
      case Message::PAYLOAD_NOT_SET:
        std::unreachable();
    }
    std::unreachable();
  }
};

// --- Servis İş Mantığı (CPU-intensive işlemler worker thread'inde çalışır) ---
class AppBusinessService {
 public:
  std::optional<Message> Handle(GlobalDomain&& msg) {
    Message reply;
    reply.case_ = Message::kOutputMessage;
    reply.output_.code_ = (msg.v2_id > 0) ? 200 : 400;
    return reply;
  }

  std::optional<Message> Handle(InputDomain&&) {
    Message ack;
    ack.case_ = Message::kOutputMessage;
    ack.output_.code_ = 200;
    return ack;
  }

  std::optional<Message> Handle(OutputDomain&&) { return std::nullopt; }
};

inline void RunServiceA() {
  boost::asio::io_context io_ctx;
  MessageMapper mapper;
  AppBusinessService service;

  net::TcpServer<net::LengthCodec> server{
      io_ctx, {.port = 9001, .worker_threads = 4}};

  // Doğrudan worker thread'inde çalışır (sıfır boilerplate)
  server.OnFrame([&](auto session, std::span<const std::byte> bytes) {
    thread_local proto::ProtoParser parser;

    auto domain = parser.Parse<Message, kMessageSpec>(
        bytes, [&](const Message& p) { return mapper.Map(p); });

    if (!domain) [[unlikely]] {
      LogPipelineError(session->Id(), domain.error());
      return;
    }

    std::visit(
        [&](auto&& msg) {
          if (auto reply = service.Handle(std::move(msg))) {
            session->Send(*reply);  // [4B len + proto]
          }
        },
        std::move(*domain));
  });

  server.Start();
  io_ctx.run();
}

}  // namespace repo1

// ============================================================================
// REPO 2 (Servis B): [4B msg_id] + [4B len] + [proto] — Çoklu bağımsız proto
// ============================================================================
namespace repo2 {

constexpr std::uint32_t kAuthReqId = 1001;
constexpr std::uint32_t kAuthRespId = 1002;
constexpr std::uint32_t kOrderReqId = 2001;
constexpr std::uint32_t kOrderRespId = 2002;

struct AuthReq {
  bool ParseFromArray(const void*, int) { return true; }
  const std::string& token() const { return token_; }
  std::string token_;
};

struct AuthResp {
  std::size_t ByteSizeLong() const { return 8; }
  bool SerializeToArray(void*, int) const { return true; }
  bool ok = false;
};

struct OrderReq {
  bool ParseFromArray(const void*, int) { return true; }
  std::uint64_t order_id() const { return order_id_; }
  double price() const { return price_; }
  std::uint64_t order_id_ = 0;
  double price_ = 0.0;
};

struct OrderResp {
  std::size_t ByteSizeLong() const { return 8; }
  bool SerializeToArray(void*, int) const { return true; }
  bool accepted = false;
};

using namespace proto;

inline constexpr Spec kAuthSpec{
    Rule<&AuthReq::token>("token", NotEmpty{}),
};

inline constexpr Spec kOrderSpec{
    Rule<&OrderReq::order_id>("order_id", Between<std::uint64_t>{1, UINT64_MAX}),
    Rule<&OrderReq::price>("price", Between<double>{0.01, 1'000'000.0}),
};

struct AuthDomain {
  std::string token;
};
struct OrderDomain {
  std::uint64_t order_id;
  double price;
};

struct AuthMapper {
  AuthDomain Map(const AuthReq& p) const { return AuthDomain{p.token()}; }
};

struct OrderMapper {
  std::expected<OrderDomain, MappingError> Map(const OrderReq& p) const {
    return OrderDomain{.order_id = p.order_id(), .price = p.price()};
  }
};

struct AuthService {
  AuthResp Handle(AuthDomain&& req) {
    return AuthResp{.ok = (req.token == "secret")};
  }
};

struct OrderService {
  OrderResp Handle(OrderDomain&& req) {
    return OrderResp{.accepted = (req.price > 0.0)};
  }
};

inline void RunServiceB() {
  boost::asio::io_context io_ctx;
  AuthMapper auth_mapper;
  OrderMapper order_mapper;
  AuthService auth_service;
  OrderService order_service;

  net::TcpServer<net::MsgIdLengthCodec> server{
      io_ctx, {.port = 9002, .worker_threads = 4}};

  server.OnFrame([&](auto session, net::MsgIdMeta meta,
                     std::span<const std::byte> bytes) {
    // Tüm msg_id'ler için worker başına tek paylaşımlı Arena
    thread_local proto::ProtoParser parser;

    switch (meta.msg_id) {
      case kAuthReqId: {
        auto req = parser.Parse<AuthReq, kAuthSpec>(
            bytes, [&](const AuthReq& p) { return auth_mapper.Map(p); });
        if (!req) [[unlikely]] {
          LogPipelineError(session->Id(), req.error());
          return;
        }
        AuthResp resp = auth_service.Handle(std::move(*req));
        session->Send(kAuthRespId, resp);  // [4B id + 4B len + proto]
        break;
      }
      case kOrderReqId: {
        auto req = parser.Parse<OrderReq, kOrderSpec>(
            bytes, [&](const OrderReq& p) { return order_mapper.Map(p); });
        if (!req) [[unlikely]] {
          LogPipelineError(session->Id(), req.error());
          return;
        }
        OrderResp resp = order_service.Handle(std::move(*req));
        session->Send(kOrderRespId, resp);
        break;
      }
      default:
        std::cerr << "[session=" << session->Id()
                  << "] Unknown msg_id=" << meta.msg_id << '\n';
        break;
    }
  });

  server.Start();
  io_ctx.run();
}

}  // namespace repo2
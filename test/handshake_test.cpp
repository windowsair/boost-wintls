//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "async_echo_client.hpp"
#include "async_echo_server.hpp"
#include "certificate.hpp"
#include "tls_record.hpp"
#include "unittest.hpp"

#include <wintls.hpp>
#include "asio_ssl_server_stream.hpp"
#include "asio_ssl_client_stream.hpp"
#include "wintls_client_stream.hpp"
#include "wintls_server_stream.hpp"

#ifdef WINTLS_USE_STANDALONE_ASIO
const auto& get_system_category = std::system_category;
#define WINTLS_TEST_ERROR_NAMESPACE_ALIAS() \
  using std::errc; \
  namespace err_help = std;
#else // WINTLS_USE_STANDALONE_ASIO
const auto& get_system_category = boost::system::system_category;
#define WINTLS_TEST_ERROR_NAMESPACE_ALIAS()
  using namespace boost::system; \
  namespace err_help = boost::system::errc;
#endif // !WINTLS_USE_STANDALONE_ASIO

namespace wintls {

std::ostream& operator<<(std::ostream& os, const method meth) {
  switch (meth) {
    case method::system_default:
      return os << "system_default";
    case method::sslv3:
      return os << "sslv3";
    case method::sslv3_client:
      return os << "sslv3_client";
    case method::sslv3_server:
      return os << "sslv3_server";
    case method::tlsv1:
      return os << "tlsv1";
    case method::tlsv1_client:
      return os << "tlsv1_client";
    case method::tlsv1_server:
      return os << "tlsv1_server";
    case method::tlsv11:
      return os << "tlsv11";
    case method::tlsv11_client:
      return os << "tlsv11_client";
    case method::tlsv11_server:
      return os << "tlsv11_server";
    case method::tlsv12:
      return os << "tlsv12";
    case method::tlsv12_client:
      return os << "tlsv12_client";
    case method::tlsv12_server:
      return os << "tlsv12_server";
    case method::tlsv13:
      return os << "tlsv13";
    case method::tlsv13_client:
      return os << "tlsv13_client";
    case method::tlsv13_server:
      return os << "tlsv13_server";
  }
  WINTLS_UNREACHABLE_RETURN(0);
}

} // namespace wintls

namespace {

std::string wchar_to_string(const wchar_t* input) {
  const auto length = static_cast<int>(std::wcslen(input));

  const auto size_needed = WideCharToMultiByte(CP_UTF8, 0, input, length, nullptr, 0, nullptr, nullptr);
  if (size_needed == 0) {
    wintls::detail::throw_last_error("WideCharToMultiByte");
  }

  std::string output(static_cast<std::size_t>(size_needed), '\0');
  const auto size_written = WideCharToMultiByte(CP_UTF8, 0, input, length, &output[0], size_needed, nullptr, nullptr);
  if (size_written == 0) {
    wintls::detail::throw_last_error("WideCharToMultiByte");
  }
  return output;
}

std::vector<BYTE> string_to_x509_name(const std::string& str) {
  DWORD size = 0;
  std::vector<BYTE> ret;
  if (!CertStrToName(X509_ASN_ENCODING, str.c_str(), CERT_X500_NAME_STR, nullptr, nullptr, &size, nullptr)) {
    wintls::detail::throw_last_error("CertStrToName");
  }
  ret.resize(size);
  if (!CertStrToName(X509_ASN_ENCODING, str.c_str(), CERT_X500_NAME_STR, nullptr, ret.data(), &size, nullptr)) {
    wintls::detail::throw_last_error("CertStrToName");
  }
  return ret;
}

struct cert_name_blob {
  cert_name_blob(const std::string& str)
    : data_(string_to_x509_name(str)) {
    blob.pbData = data_.data();
    blob.cbData = static_cast<DWORD>(data_.size());
  }

  CERT_NAME_BLOB blob;
private:
  std::vector<BYTE> data_;
};

wintls::cert_context_ptr create_self_signed_cert(const std::string& subject) {
  cert_name_blob cert_subject(subject);
  SYSTEMTIME expiry_date;
  GetSystemTime(&expiry_date);
  expiry_date.wYear += 1;

  auto cert = CertCreateSelfSignCertificate(0,
                                            &cert_subject.blob,
                                            0,
                                            0,
                                            nullptr,
                                            0,
                                            &expiry_date,
                                            0);
  if (!cert) {
    wintls::detail::throw_last_error("CertCreateSelfSignCertificate");
  }
  return wintls::cert_context_ptr{cert};
}

std::string cert_container_name(const CERT_CONTEXT* cert) {
  DWORD size = 0;
  if (!CertGetCertificateContextProperty(cert,
                                         CERT_KEY_PROV_INFO_PROP_ID,
                                         nullptr,
                                         &size)) {
    wintls::detail::throw_last_error("CertGetCertificateContextProperty");
  }

  std::vector<BYTE> data(size);
  if (!CertGetCertificateContextProperty(cert,
                                         CERT_KEY_PROV_INFO_PROP_ID,
                                         data.data(),
                                         &size)) {
    wintls::detail::throw_last_error("CertGetCertificateContextProperty");
  }
  const auto info = reinterpret_cast<CRYPT_KEY_PROV_INFO*>(data.data());
  return wchar_to_string(info->pwszContainerName);
}
} // namespace

TEST_CASE("certificates") {
  using namespace std::string_literals;
  WINTLS_TEST_ERROR_NAMESPACE_ALIAS();

  net::io_context io_context;
  wintls::context client_ctx(wintls::method::system_default);
  wintls::stream<test_stream> client_stream(io_context, client_ctx);

  SECTION("invalid certificate data") {
    // TODO: Instead of returning an error when given a null pointer
    // or other easily detectable invalid input, the Windows crypto
    // libraries cause the Windows equivalent of a segfault. This is
    // pretty consistent with the rest of the Windows API though.
    //
    // Figure out a way to generate invalid data that doesn't make the
    // test crash.
    /*
    using namespace boost::system;

    auto error = errc::make_error_code(errc::not_supported);

    CERT_INFO cert_info{};
    const CERT_CONTEXT bad_cert{
      X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
      nullptr,
      0,
      &cert_info,
      0};
    client_ctx.add_certificate_authority(&bad_cert, error);

    CHECK(error.category() == boost::system::system_category());
    CHECK(error.value() == CRYPT_E_ASN1_EOD);
    */
  }

  SECTION("server cert without private key") {
    wintls::context server_ctx(wintls::method::system_default);
    auto cert = x509_to_cert_context(net::buffer(test_certificate), wintls::file_format::pem);

    CHECK_THROWS_WITH(server_ctx.use_certificate(cert.get()),
                      Catch::Matchers::Contains("Cannot find the certificate and private key for decryption"));

    error_code ec{};
    server_ctx.use_certificate(cert.get(), ec);
    CHECK(ec.category() == get_system_category());
    CHECK(ec.value() & NTE_BAD_SIGNATURE);
  }

  SECTION("wintl server") {
    wintls::context server_ctx(wintls::method::system_default);
    const auto cert = create_self_signed_cert("CN=WinTLS, T=Test");
    server_ctx.use_certificate(cert.get());
    wintls::stream<test_stream> server_stream(io_context, server_ctx);

    client_stream.next_layer().connect(server_stream.next_layer());

    SECTION("no certificate validation") {
      auto client_error = err_help::make_error_code(errc::not_supported);
      client_stream.async_handshake(wintls::handshake_type::client,
                                    [&client_error, &io_context](const error_code& ec) {
                                      client_error = ec;
                                      io_context.stop();
                                    });

      auto server_error = err_help::make_error_code(errc::not_supported);
      server_stream.async_handshake(wintls::handshake_type::server,
                                    [&server_error](const error_code& ec) {
                                      server_error = ec;
                                    });
      io_context.run();
      CHECK_FALSE(client_error);
      CHECK_FALSE(server_error);
    }

    SECTION("no trusted certificate") {
      client_ctx.verify_server_certificate(true);

      auto client_error = err_help::make_error_code(errc::not_supported);
      client_stream.async_handshake(wintls::handshake_type::client,
                                    [&client_error](const error_code& ec) {
                                      client_error = ec;
                                    });

      auto server_error = err_help::make_error_code(errc::not_supported);
      server_stream.async_handshake(wintls::handshake_type::server,
                                    [&server_error](const error_code& ec) {
                                      server_error = ec;
                                    });

      io_context.run();
      CHECK(client_error.category() == get_system_category());
      CHECK(client_error.value() == CERT_E_UNTRUSTEDROOT);
      CHECK_FALSE(server_error);
    }

    SECTION("trusted certificate verified") {
      client_ctx.verify_server_certificate(true);
      client_ctx.add_certificate_authority(cert.get());

      auto client_error = err_help::make_error_code(errc::not_supported);
      client_stream.async_handshake(wintls::handshake_type::client,
                                    [&client_error, &io_context](const error_code& ec) {
                                      client_error = ec;
                                      io_context.stop();
                                    });

      auto server_error = err_help::make_error_code(errc::not_supported);
      server_stream.async_handshake(wintls::handshake_type::server,
                                    [&server_error](const error_code& ec) {
                                      server_error = ec;
                                    });
      io_context.run();
      CHECK_FALSE(client_error);
      CHECK_FALSE(server_error);
    }

    wintls::delete_private_key(cert_container_name(cert.get()));
  }

  SECTION("asio::ssl server") {
    net::ssl::context server_ctx(net::ssl::context::tls_server);
    server_ctx.use_certificate_chain(net::buffer(test_certificate));
    server_ctx.use_private_key(net::buffer(test_key), net::ssl::context::pem);

    net::ssl::stream<test_stream> server_stream(io_context, server_ctx);

    client_stream.next_layer().connect(server_stream.next_layer());

    SECTION("no certificate validation") {
      auto client_error = err_help::make_error_code(errc::not_supported);
      client_stream.async_handshake(wintls::handshake_type::client,
                                    [&client_error, &io_context](const error_code& ec) {
                                      client_error = ec;
                                      io_context.stop();
                                    });

      auto server_error = err_help::make_error_code(errc::not_supported);
      server_stream.async_handshake(asio_ssl::stream_base::server,
                                    [&server_error](const error_code& ec) {
                                      server_error = ec;
                                    });
      io_context.run();
      CHECK_FALSE(client_error);
      CHECK_FALSE(server_error);
    }

    SECTION("no trusted certificate") {
      client_ctx.verify_server_certificate(true);

      auto client_error = err_help::make_error_code(errc::not_supported);
      client_stream.async_handshake(wintls::handshake_type::client,
                                    [&client_error](const error_code& ec) {
                                      client_error = ec;
                                    });

      auto server_error = err_help::make_error_code(errc::not_supported);
      server_stream.async_handshake(asio_ssl::stream_base::server,
                                    [&server_error](const error_code& ec) {
                                      server_error = ec;
                                    });

      io_context.run();
      CHECK(client_error.category() == get_system_category());
      CHECK(client_error.value() == CERT_E_UNTRUSTEDROOT);
      CHECK_FALSE(server_error);
    }

    SECTION("trusted certificate verified") {
      client_ctx.verify_server_certificate(true);

      const auto cert_ptr = x509_to_cert_context(net::buffer(test_certificate), wintls::file_format::pem);
      client_ctx.add_certificate_authority(cert_ptr.get());

      auto client_error = err_help::make_error_code(errc::not_supported);
      client_stream.async_handshake(wintls::handshake_type::client,
                                    [&client_error, &io_context](const error_code& ec) {
                                      client_error = ec;
                                      io_context.stop();
                                    });

      auto server_error = err_help::make_error_code(errc::not_supported);
      server_stream.async_handshake(asio_ssl::stream_base::server,
                                    [&server_error](const error_code& ec) {
                                      server_error = ec;
                                    });
      io_context.run();
      CHECK_FALSE(client_error);
      CHECK_FALSE(server_error);
    }
  }
}

TEST_CASE("client certificates") {
  using namespace std::string_literals;

  SECTION("wintls client certificate missing with openssl server") {
    WINTLS_TEST_ERROR_NAMESPACE_ALIAS();

    wintls_client_context client_ctx;
    asio_ssl_server_context server_ctx;
    server_ctx.enable_client_verify();

    net::io_context io_context;
    wintls::stream<test_stream> client_stream(io_context, client_ctx);
    net::ssl::stream<test_stream> server_stream(io_context, server_ctx);

    client_stream.next_layer().connect(server_stream.next_layer());

    auto client_error = err_help::make_error_code(errc::not_supported);
    client_stream.async_handshake(wintls::handshake_type::client,
                                  [&client_error](const error_code& ec) {
                                    client_error = ec;
                                  });

    auto server_error = err_help::make_error_code(errc::not_supported);
    server_stream.async_handshake(asio_ssl::stream_base::server,
                                  [&server_error](const error_code& ec) {
                                    server_error = ec;
                                  });
    io_context.run();
    // client handshake is failed by server
    CHECK(client_error);
    // Note: The server error code is 0xa0000c7 or 0xc0c7 depends on the int size
    // and expected error code is 199. Error message is correct.
    // Seems like the error code lower bits are right, take the lower 2 bytes of the int.
    // It is unclear why this happens.
    CHECK_THAT(server_error.message(), Catch::Contains("peer did not return a certificate"));
    CHECK((server_error.value() & 0xff) == SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE);
  }

  SECTION("trusted wintls client certificate verified on openssl server") {
    WINTLS_TEST_ERROR_NAMESPACE_ALIAS();

    wintls_client_context client_ctx;
    client_ctx.with_test_client_cert(); // Note that if client cert is supplied, sspi will verify server cert with it.
    client_ctx.verify_server_certificate(true);

    asio_ssl_server_context server_ctx;
    server_ctx.enable_client_verify();

    net::io_context io_context;
    wintls::stream<test_stream> client_stream(io_context, client_ctx);
    net::ssl::stream<test_stream> server_stream(io_context, server_ctx);

    client_stream.next_layer().connect(server_stream.next_layer());

    auto client_error = err_help::make_error_code(errc::not_supported);
    client_stream.async_handshake(wintls::handshake_type::client,
                                  [&client_error](const error_code& ec) {
                                    client_error = ec;
                                  });

    auto server_error = err_help::make_error_code(errc::not_supported);
    server_stream.async_handshake(asio_ssl::stream_base::server,
                                  [&server_error](const error_code& ec) {
                                    server_error = ec;
                                  });
    io_context.run();
    CHECK_FALSE(client_error);
    CHECK_FALSE(server_error);
  }

  SECTION("trusted openssl client certificate verified on openssl server") {
    WINTLS_TEST_ERROR_NAMESPACE_ALIAS();

    asio_ssl_client_context client_ctx;
    client_ctx.with_test_client_cert();
    client_ctx.enable_server_verify();

    asio_ssl_server_context server_ctx;
    server_ctx.enable_client_verify();

    net::io_context io_context;
    net::ssl::stream<test_stream> client_stream(io_context, client_ctx);
    net::ssl::stream<test_stream> server_stream(io_context, server_ctx);

    client_stream.next_layer().connect(server_stream.next_layer());

    auto client_error = err_help::make_error_code(errc::not_supported);
    client_stream.async_handshake(asio_ssl::stream_base::client,
                                  [&client_error](const error_code& ec) {
                                    client_error = ec;
                                  });

    auto server_error = err_help::make_error_code(errc::not_supported);
    server_stream.async_handshake(asio_ssl::stream_base::server,
                                  [&server_error](const error_code& ec) {
                                    server_error = ec;
                                  });
    io_context.run();
    CHECK_FALSE(client_error);
    CHECK_FALSE(server_error);
  }

  SECTION("trusted openssl client certificate verified on wintls server") {
    WINTLS_TEST_ERROR_NAMESPACE_ALIAS();

    asio_ssl_client_context client_ctx;
    client_ctx.with_test_client_cert();
    client_ctx.enable_server_verify();

    wintls_server_context server_ctx;
    server_ctx.enable_client_verify();

    net::io_context io_context;
    net::ssl::stream<test_stream> client_stream(io_context, client_ctx);
    wintls::stream<test_stream> server_stream(io_context, server_ctx);

    client_stream.next_layer().connect(server_stream.next_layer());

    auto client_error = err_help::make_error_code(errc::not_supported);
    client_stream.async_handshake(asio_ssl::stream_base::client,
                                  [&client_error](const error_code& ec) {
                                    client_error = ec;
                                  });

    auto server_error = err_help::make_error_code(errc::not_supported);
    server_stream.async_handshake(wintls::handshake_type::server,
                                  [&server_error](const error_code& ec) {
                                    server_error = ec;
                                  });
    io_context.run();
    CHECK_FALSE(client_error);
    CHECK_FALSE(server_error);
  }

  SECTION("openssl client missing certificate on wintls server") {
    WINTLS_TEST_ERROR_NAMESPACE_ALIAS();

    asio_ssl_client_context client_ctx;

    wintls_server_context server_ctx;
    server_ctx.enable_client_verify();

    net::io_context io_context;
    net::ssl::stream<test_stream> client_stream(io_context, client_ctx);
    wintls::stream<test_stream> server_stream(io_context, server_ctx);

    client_stream.next_layer().connect(server_stream.next_layer());

    auto client_error = err_help::make_error_code(errc::not_supported);
    client_stream.async_handshake(asio_ssl::stream_base::client,
                                  [&client_error](const error_code& ec) {
                                    client_error = ec;
                                  });

    auto server_error = err_help::make_error_code(errc::not_supported);
    server_stream.async_handshake(wintls::handshake_type::server,
                                  [&server_error](const error_code& ec) {
                                    server_error = ec;
                                  });
    io_context.run();
    CHECK_FALSE(client_error);
    CHECK(server_error.value() == SEC_E_NO_CREDENTIALS);
  }

  SECTION("trusted wintls client certificate verified on wintls server") {
    WINTLS_TEST_ERROR_NAMESPACE_ALIAS();

    wintls_client_context client_ctx;
    client_ctx.with_test_client_cert();
    client_ctx.enable_server_verify();

    wintls_server_context server_ctx;
    server_ctx.enable_client_verify();

    net::io_context io_context;
    wintls::stream<test_stream> client_stream(io_context, client_ctx);
    wintls::stream<test_stream> server_stream(io_context, server_ctx);

    client_stream.next_layer().connect(server_stream.next_layer());

    auto client_error = err_help::make_error_code(errc::not_supported);
    client_stream.async_handshake(wintls::handshake_type::client,
                                  [&client_error](const error_code& ec) {
                                    client_error = ec;
                                  });

    auto server_error = err_help::make_error_code(errc::not_supported);
    server_stream.async_handshake(wintls::handshake_type::server,
                                  [&server_error](const error_code& ec) {
                                    server_error = ec;
                                  });
    io_context.run();
    CHECK_FALSE(client_error);
    CHECK_FALSE(server_error);
  }
}

TEST_CASE("failing handshakes") {
  wintls::context client_ctx(wintls::method::system_default);
  net::io_context io_context;
  wintls::stream<test_stream> client_stream(io_context, client_ctx);
  test_stream server_stream(io_context);

  client_stream.next_layer().connect(server_stream);

  SECTION("invalid server reply") {
    WINTLS_TEST_ERROR_NAMESPACE_ALIAS();

    auto error = err_help::make_error_code(errc::not_supported);
    client_stream.async_handshake(wintls::handshake_type::client,
                                  [&error](const error_code& ec) {
                                    error = ec;
                                  });

    std::array<char, 1024> buffer;
    server_stream.async_read_some(net::buffer(buffer, buffer.size()),
                                  [&buffer, &server_stream](const error_code&, std::size_t length) {
                                    tls_record rec(net::buffer(buffer, length));
                                    REQUIRE(rec.type == tls_record::record_type::handshake);
                                    auto handshake = variant::get<tls_handshake>(rec.message);
                                    REQUIRE(handshake.type == tls_handshake::handshake_type::client_hello);
                                    // Echoing the client_hello message back should cause the handshake to fail
                                    net::write(server_stream, net::buffer(buffer));
                                  });

    io_context.run();
    CHECK(error.category() == get_system_category());
    CHECK(error.value() == SEC_E_ILLEGAL_MESSAGE);
  }
}

TEST_CASE("ssl/tls versions") {
  const auto value = GENERATE(values<std::pair<wintls::method, tls_version>>({
        { wintls::method::tlsv1, tls_version::tls_1_0 },
        { wintls::method::tlsv1_client, tls_version::tls_1_0 },
        { wintls::method::tlsv11, tls_version::tls_1_1 },
        { wintls::method::tlsv11_client, tls_version::tls_1_1 },
        { wintls::method::tlsv12, tls_version::tls_1_2 },
        { wintls::method::tlsv12_client, tls_version::tls_1_2 },
        { wintls::method::tlsv13, tls_version::tls_1_3 },
        { wintls::method::tlsv13_client, tls_version::tls_1_3 }
      })
    );

  const auto method = value.first;
  const auto version = value.second;

  wintls::context client_ctx(method);
  net::io_context io_context;
  wintls::stream<test_stream> client_stream(io_context, client_ctx);
  test_stream server_stream(io_context);

  client_stream.next_layer().connect(server_stream);

  client_stream.async_handshake(wintls::handshake_type::client,
                                [method, &io_context](const error_code& ec) {
                                  if (ec.value() == SEC_E_ALGORITHM_MISMATCH) {
                                    WARN("Protocol not supported: " << method);
                                    io_context.stop();
                                    return;
                                  }
                                  REQUIRE(ec == net::error::eof);
                                });

  std::array<char, 1024> buffer;
  server_stream.async_read_some(net::buffer(buffer, buffer.size()),
                                [&buffer, &server_stream, &version](const error_code&, std::size_t length) {
                                  tls_record rec(net::buffer(buffer, length));
                                  REQUIRE(rec.type == tls_record::record_type::handshake);
                                  if (version != tls_version::tls_1_3) {
                                    CHECK(rec.version == version);
                                  } else {
                                    bool support_tls_v1_3 = false;

                                    if (rec.type == tls_record::record_type::handshake) {
                                      tls_handshake& handshake = variant::get<tls_handshake>(rec.message);
                                      auto& extension = variant::get<tls_handshake::client_hello>(handshake.message).extension;

                                      auto it = std::find_if(extension.begin(), extension.end(), [](const tls_extension& s) {
                                        return s.type == tls_extension::extension_type::supported_versions;
                                      });

                                      if (it != extension.end()) {
                                        auto& versions = variant::get<tls_extension::supported_versions>(it->message).version;
                                        support_tls_v1_3 = std::any_of(versions.begin(), versions.end(), [](const auto& s) {
                                          return s == tls_version::tls_1_3;
                                        });
                                      }
                                    }

                                    REQUIRE(support_tls_v1_3);
                                  }
                                  server_stream.close();
                                });

    io_context.run();
}

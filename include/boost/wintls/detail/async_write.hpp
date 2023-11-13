//
// Copyright (c) 2020 Kasper Laudrup (laudrup at stacktrace dot dk)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#ifndef BOOST_WINTLS_DETAIL_ASYNC_WRITE_HPP
#define BOOST_WINTLS_DETAIL_ASYNC_WRITE_HPP

#include <boost/wintls/detail/config.hpp>
#include <boost/wintls/detail/sspi_encrypt.hpp>

#ifdef WINTLS_USE_STANDALONE_ASIO
#include <asio/coroutine.hpp>
#else
#include <boost/asio/coroutine.hpp>
#endif


namespace boost {
namespace wintls {
namespace detail {

template <typename NextLayer, typename ConstBufferSequence>
struct async_write : net::coroutine {
  async_write(NextLayer& next_layer, const ConstBufferSequence& buffer, detail::sspi_encrypt& encrypt)
    : next_layer_(next_layer)
    , buffer_(buffer)
    , encrypt_(encrypt) {
  }

  template <typename Self>
  void operator()(Self& self, wintls::error_code ec = {}, std::size_t length = 0) {
    (void)(length);
    WINTLS_ASIO_CORO_REENTER(*this) {
      bytes_consumed_ = encrypt_(buffer_, ec);
      if (ec) {
        self.complete(ec, 0);
        return;
      }

      WINTLS_ASIO_CORO_YIELD {
        net::async_write(next_layer_, encrypt_.buffers, std::move(self));
      }
      self.complete(ec, bytes_consumed_);
    }
  }

private:
  NextLayer& next_layer_;
  ConstBufferSequence buffer_;
  detail::sspi_encrypt& encrypt_;
  size_t bytes_consumed_{0};
};

} // detail
} // namespace wintls
} // namespace boost

#endif // BOOST_WINTLS_DETAIL_ASYNC_WRITE_HPP

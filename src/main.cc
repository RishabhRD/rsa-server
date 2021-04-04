#include "Decryptor.h"
#include "KeyCalculator.h"
#include <asio.hpp>
#include <iostream>
#include <string>

using asio::ip::tcp;
using namespace std;

int main() {
  try {
    asio::io_context io_context;
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8080));
    tcp::socket socket(io_context);
    acceptor.accept(socket);
    KeyCalculator calc(11, 17, 3);
    auto keys = calc.getKeyPair();
    cout<<"Public key: "<<keys.first.m<<" "<<keys.first.r<<endl;
    asio::write(socket, asio::buffer(&keys.first, sizeof(keys.first)));
    Decryptor decryptor(keys.second);
    std::string decryptedString;
    for (;;) {
      CryptoString readString(1024);
      std::error_code error;
      size_t len = socket.read_some(asio::buffer(readString), error);
      if(error == asio::error::eof){
        break;
      }else if(error){
        throw std::system_error(error);
      }
      if(readString.size() == 0){
        continue;
      }
      decryptedString = decryptor.decryptString(readString);
      std::cout << decryptedString << std::endl;
    }
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
}

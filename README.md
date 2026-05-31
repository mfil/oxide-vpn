# OxideVPN

OpenVPN client in Rust, with the obligatory rust joke in the name.

This client is **very far** from being ready for actual use, and I don't know if it will ever get
there. For now, it "works" with the following caveats:

* Linux only.
* It is compatible only with recent versions of OpenVPN. I'm not aiming for compatibility with older
  versions to keep this project manageable.
* In particular, it requires the new aead-epoch data channel protocol. You might need to disable DCO
  on the server.
* No support for renegotiation.
* The user needs to set the IP address for the tun interface themselves.

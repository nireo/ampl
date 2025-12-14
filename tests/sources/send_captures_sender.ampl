def logger() {
    msg = recv(from);
    print(msg);
    print(from);
}

child = spawn(logger);
parent = self();
send(child, 9);

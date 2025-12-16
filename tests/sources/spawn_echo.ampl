def worker() {
    msg = recv(parent);
    send(parent, :reply, msg + 1);
}

parent = self();
child = spawn(worker);
send(child, :ping, 5);
print(recv());

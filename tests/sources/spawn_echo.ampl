def worker() {
    msg = recv(parent);
    send(parent, msg + 1);
}

parent = self();
child = spawn(worker);
send(child, 5);
print(recv());

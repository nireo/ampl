# ampl: Actor Message Programming Language

A simple concurrency focused programming language. Currently the only pieces of the VM are implemented.

## Example syntax

This is some syntax I had in mind.

```
def pong() {
    loop {
        let msg = recv();
        send(msg.sender, :pong, msg.value + 1);
    }
}

let p = spawn { pong() };

send(p, :ping, { sender: self, value: 0 });

let reply = recv();
print(reply.value);  # 1
```

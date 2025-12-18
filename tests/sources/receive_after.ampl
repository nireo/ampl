receive {
    {:ping, data} -> print(data);
} after 1 -> print(42);

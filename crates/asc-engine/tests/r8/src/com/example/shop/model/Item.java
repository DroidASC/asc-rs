package com.example.shop.model;

public class Item {
    public final String name;
    public final int price;
    Item next;

    public Item(String name, int price) {
        this.name = name;
        this.price = price;
    }

    public int price() {
        if (name.isEmpty()) {
            throw new IllegalStateException("empty " + price);
        }
        return price * 3 + name.hashCode();
    }

    @Override
    public String toString() {
        return name + "=" + price;
    }
}

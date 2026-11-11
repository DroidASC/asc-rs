package com.example.shop.model;

import java.util.ArrayList;
import java.util.List;

public class Cart {
    private final List<Item> items = new ArrayList<>();
    private final List<Line> lines = new ArrayList<>();
    private Item last;
    private int capacity;

    public Cart(int capacity) {
        this.capacity = capacity;
    }

    public void add(Item item) {
        checkCapacity();
        items.add(item);
        if (last != null) {
            last.next = item;
        }
        last = item;
    }

    public void add(String name, int quantity) {
        checkCapacity();
        lines.add(new Line(this, name, quantity));
    }

    private void checkCapacity() {
        if (items.size() + lines.size() > capacity * 4 + 10) {
            throw new IllegalStateException("full: " + capacity);
        }
    }

    public Item[] items() {
        return items.toArray(new Item[0]);
    }

    public Line[] lines() {
        return lines.toArray(new Line[0]);
    }

    public String describe(int n) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < n && i < items.size(); i++) {
            sb.append(items.get(i)).append(';');
        }
        return sb.toString();
    }

    public String describe(String prefix) {
        StringBuilder sb = new StringBuilder(prefix);
        for (Line l : lines) {
            sb.append(l.name).append('x').append(l.quantity).append(';');
        }
        return sb.toString();
    }

    public Runnable watcher(final String[] args) {
        return new Runnable() {
            @Override
            public void run() {
                for (String a : args) {
                    System.out.println(a + items.size() + lines.size());
                }
            }
        };
    }

    public static class Line {
        final Cart owner;
        final String name;
        final int quantity;

        Line(Cart owner, String name, int quantity) {
            this.owner = owner;
            this.name = name;
            this.quantity = quantity;
        }

        public long cost(Item[] catalog, int unused) {
            long c = 0;
            for (Item i : catalog) {
                if (i.name.equals(name)) {
                    c += (long) i.price() * quantity;
                } else if (i.name.length() == name.length()) {
                    c += i.name.compareTo(name) * (long) quantity;
                    System.out.println("near " + i + " for " + name + " in " + owner.describe(quantity));
                } else if (c > 1000) {
                    c -= owner.capacity + quantity;
                }
            }
            return c + owner.capacity;
        }

        public static class Tag {
            public final String label;

            private Tag(String label) {
                this.label = label;
            }

            public static Tag of(int n) {
                return n > 3 ? new Tag("many:" + n) : new Tag("few:" + n);
            }
        }
    }
}

package com.example.shop.util;

import com.example.shop.model.Cart;
import com.example.shop.model.Item;

public final class Pricing {
    private static int calls;

    private Pricing() {}

    public static long total(Item[] items, boolean discount) {
        long t = 0;
        for (Item i : items) {
            t += i.price();
            calls++;
            if (t > 1_000_000L) {
                System.out.println("big " + i + " at " + calls);
                t = t % 1_000_000L + calls;
            }
        }
        return discount ? t - t / 10 : t;
    }

    public static long total(Cart.Line[] lines) {
        long t = 0;
        for (Cart.Line l : lines) {
            t += l.cost(new Item[0], lines.length);
            calls++;
            if (t > 1_000_000L) {
                System.out.println("big " + l + " at " + calls);
                t = t % 1_000_000L + calls;
            }
        }
        return t;
    }

    public static long audit(Cart.Line[] lines, Item[] catalog) {
        long t = 0;
        for (Cart.Line l : lines) {
            long c = l.cost(catalog, calls);
            if (c < 0) {
                System.out.println("negative " + l + " " + c + " at " + calls);
            }
            t ^= c * 31 + calls;
        }
        return t;
    }

    public static String format(long total, Cart cart) {
        return "total=" + total + " " + cart.describe(1);
    }
}

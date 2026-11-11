package com.example.shop;

import com.example.shop.model.Cart;
import com.example.shop.model.Item;
import com.example.shop.util.Pricing;

public class Main {
    public static void main(String[] args) {
        Cart cart = new Cart(args.length);
        for (String a : args) {
            cart.add(new Item(a, a.length()));
            cart.add(a, args.length);
        }
        Item[] items = cart.items();
        Cart.Line[] lines = cart.lines();
        long total = Pricing.total(items, args.length > 2);
        total += Pricing.total(lines);
        total += Pricing.total(cart.items(), args.length > 5);
        total += Pricing.total(cart.lines());
        total += Pricing.audit(lines, items) + Pricing.audit(cart.lines(), new Item[] {new Item("z", 1)});
        System.out.println(Pricing.format(total, cart));
        Runnable r = cart.watcher(args);
        r.run();
        System.out.println(cart.describe(args.length));
        System.out.println(cart.describe("x" + args.length));
        System.out.println(Cart.Line.Tag.of(args.length).label);
    }
}

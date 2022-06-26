import * as assert from "assert";
import { ClientIP, Configuration } from "../ClientIP";
import "q2-test";

each<[string, string|null]>([
    ["for=123.34.56.78", "123.34.56.78"],
    ["For=123.34.56.78", "123.34.56.78"],
    ["fOr=123.34.56.78", "123.34.56.78"],
    ["FOR=123.34.56.78", "123.34.56.78"],
    ["for=123.34.56.78:4561", "123.34.56.78"],
    ["for=\"123.34.56.78\"", "123.34.56.78"],
    ["for=\"123.34.56.78:4561\"", "123.34.56.78"],
    ["for=2001:db8::1428:57ab", "2001:db8::1428:57ab"],
    ["for=[2001:db8::1428:57ab]", "2001:db8::1428:57ab"],
    ["for=[2001:db8::1428:57ab]:4561", "2001:db8::1428:57ab"],
    ["for=\"2001:db8::1428:57ab\"", "2001:db8::1428:57ab"],
    ["for=\"[2001:db8::1428:57ab]\"", "2001:db8::1428:57ab"],
    ["for=\"[2001:db8::1428:57ab]:4561\"", "2001:db8::1428:57ab"],
    ["proto=http;for=123.34.56.78;host=example.com, for=98.123.45.12", "123.34.56.78"],
    ["for=blablah", null],
    ["for=1234.32.12.32", null],
    ["forr=123.34.56.78", null],
    ["blablah", null],
    ["123.34.56.78", null],
    ["proto=http;host=example.com", null]
])
.it("Test forwarded %s => %s", ([forwarded, expected]) => {
    const ip = ClientIP.getClientIP({headers: {forwarded: forwarded}});
    assert(ip === expected);
});

each<[string, Configuration, string|null]>([
    ["for=123.34.56.78", {allowedHeaders: ["forwarded"]}, "123.34.56.78"],
    ["for=123.34.56.78", {allowedHeaders: []}, null],
    ["for=123.34.56.78;secret=abc", {allowedHeaders: [["forwarded", {secret: "abc"}]]}, "123.34.56.78"],
    ["for=123.34.56.78;secret=AbC", {allowedHeaders: [["forwarded", {secret: "AbC"}]]}, "123.34.56.78"],
    ["for=123.34.56.78;SeCreT=AbC", {allowedHeaders: [["forwarded", {secret: "AbC"}]]}, "123.34.56.78"],
    ["for=123.34.56.78;SeCreT=AbC", {allowedHeaders: [["forwarded", {SeCreT: "AbC"}]]}, "123.34.56.78"],
    ["for=123.34.56.78", {allowedHeaders: [["forwarded", {secret: "abc"}]]}, null]
])
.it("Test forwarded with config %s %s => %s", ([forwarded, config, expected]) => {
    const ip = ClientIP.getClientIP({headers: {forwarded: forwarded}}, config);
    assert(ip === expected);
});

each<[string, string|null]>([
    ["123.34.56.78", "123.34.56.78"],
    ["123.34.56.78:4561", "123.34.56.78"],
    ["2001:db8::1428:57ab", "2001:db8::1428:57ab"],
    ["[2001:db8::1428:57ab]", "2001:db8::1428:57ab"],
    ["[2001:db8::1428:57ab]:4561", "2001:db8::1428:57ab"],
    ["123.34.56.78, 98.123.45.12", "123.34.56.78"],
    ["blahblah", null],
    ["1234.32.12.32", null]
])
.it("Test forwarded for %s => %s", ([forwarded, expected]) => {
    const ip = ClientIP.getClientIP({headers: {"forwarded-for": forwarded}});
    assert(ip === expected);
});

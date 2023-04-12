;
var el = document.querySelector("img[alt=logo]").closest("a");
if (el.href != "index.html") {
    el.href = "../index.html";
}

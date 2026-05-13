document.addEventListener("DOMContentLoaded", function () {
    const menuBtn = document.getElementById("menuBtn");
    const dropdownMenu = document.getElementById("dropdownMenu");

    if (!menuBtn || !dropdownMenu) {
        console.log("Menu button or dropdown not found");
        return;
    }

    menuBtn.addEventListener("click", function (event) {
        event.stopPropagation();
        dropdownMenu.classList.toggle("show-menu");
    });

    dropdownMenu.addEventListener("click", function (event) {
        event.stopPropagation();
    });

    document.addEventListener("click", function () {
        dropdownMenu.classList.remove("show-menu");
    });
});
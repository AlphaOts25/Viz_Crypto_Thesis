document.addEventListener("DOMContentLoaded", function () {
    let currentSlide = 0;
    let slideTimer;

    const slides = document.querySelectorAll(".slide");
    const dots = document.querySelectorAll(".slider-dot");

    if (!slides.length || !dots.length) return;

    function showSlide(index) {
        slides[currentSlide].classList.remove("active");
        dots[currentSlide].classList.remove("active");

        currentSlide = index;

        slides[currentSlide].classList.add("active");
        dots[currentSlide].classList.add("active");
    }

    function nextSlide() {
        const next = (currentSlide + 1) % slides.length;
        showSlide(next);
    }

    function startAutoSlide() {
        slideTimer = setInterval(nextSlide, 3000);
    }

    function resetAutoSlide() {
        clearInterval(slideTimer);
        startAutoSlide();
    }

    dots.forEach((dot, index) => {
        dot.addEventListener("click", function () {
            showSlide(index);
            resetAutoSlide();
        });
    });

    startAutoSlide();
});
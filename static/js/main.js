// Wait for the page to fully load
document.addEventListener("DOMContentLoaded", function() {
    
    // Get all the dropdown buttons in the sidebar
    var dropdowns = document.getElementsByClassName("dropdown-btn");

    // Add a click event to each one
    for (var i = 0; i < dropdowns.length; i++) {
        dropdowns[i].addEventListener("click", function() {
            // Toggle the "active" class to change color
            this.classList.toggle("active");

            // Find the container immediately following the button
            var dropdownContent = this.nextElementSibling;
            
            // Toggle between hiding and showing the active dropdown
            if (dropdownContent.style.display === "block") {
                dropdownContent.style.display = "none";
            } else {
                dropdownContent.style.display = "block";
            }
        });
    }
});
<!-- JavaScript to handle the filter effect -->
const filterIcon = document.getElementById('filterIcon');
const filterDropdown = document.querySelector('.dropdown-content');

let filterTimeout;

function showFilterOptions() {
    filterDropdown.style.display = 'block';
    clearTimeout(filterTimeout);
}

function hideFilterOptions() {
    filterTimeout = setTimeout(() => {
        filterDropdown.style.display = 'none';
    }, 500);
}

filterIcon.addEventListener('mouseover', showFilterOptions);
filterIcon.addEventListener('mouseout', hideFilterOptions);
filterDropdown.addEventListener('mouseover', () => clearTimeout(filterTimeout));
filterDropdown.addEventListener('mouseout', hideFilterOptions);

<!-- JavaScript to handle the department filter -->
const departmentFilterDropdown = document.getElementById("departmentFilterDropdown");
const noResultsMessage = document.getElementById("noResultsMessage");

function applyFilters() {
    const selectedDepartments = Array.from(departmentFilterDropdown.querySelectorAll('input[name="department"]:checked')).map(checkbox => checkbox.value);

    const rows = document.querySelectorAll("table tbody tr");
    let hasResults = false;

    rows.forEach((row) => {
        const departmentCell = row.querySelector("td:nth-child(5)").textContent.trim();

        const isMatchingDepartment = selectedDepartments.length === 0 || selectedDepartments.includes(departmentCell);

        if (isMatchingDepartment) {
            row.style.display = "table-row";
            hasResults = true;
        } else {
            row.style.display = "none";
        }
    });

    noResultsMessage.style.display = hasResults ? "none" : "block";
}

departmentFilterDropdown.querySelectorAll('input[name="department"]').forEach((checkbox) => {
    checkbox.addEventListener("change", applyFilters);
});

applyFilters();

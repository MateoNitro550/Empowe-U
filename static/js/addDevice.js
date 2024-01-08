// JavaScript to handle the add device function
const addDeviceButton = document.getElementById("addDeviceButton");
const addDevicePopup = document.getElementById("addDevicePopup");
const closeAddDevicePopup = document.getElementById("closeAddDevicePopup");

const column_mapping = {
    'application_name': 'Application Name',
    'assigned_to': 'Assigned To',
    'category': 'Category',
    'comments': 'Comments',
    'company': 'Company',
    'department': 'Department',
    'expiration_date': 'Expiration Date',
    'ip_address': 'IP Address',
    'key_value': 'Key Value',
    'mobile_number': 'Mobile Number',
    'model': 'Model',
    'name': 'Device Name',
    'purchase_date': 'Purchase Date',
    'snid': 'SNID',
    'status': 'Status',
    'tag': 'Tag',
    'user': 'User'
};

addDeviceButton.addEventListener("click", () => {
    const currentCategory = window.location.pathname.split('/').pop();

    fetch(`/get_columns/${currentCategory}`)
        .then(response => response.json())
        .then(data => {
            const formFields = data.columns.map(column => {
                if (column === data.columns[0]) {
                    return '';
                }

                return `
                    <label for="${column}">${column_mapping[column] || column}:</label>
                    <input type="text" id="${column}" name="${column}" required>
                    <br>
                `;
            }).join('');

            const submitButton = '<button type="submit">Add Device</button>';

            document.getElementById("addDeviceForm").innerHTML = formFields + submitButton;

            document.getElementById("addDeviceForm").innerHTML += `<input type="hidden" name="category" value="${currentCategory}">`;

            addDevicePopup.style.display = "block";
        });
});

closeAddDevicePopup.addEventListener("click", () => {
    addDevicePopup.style.display = "none";
});

window.addEventListener("click", (event) => {
    if (event.target === addDevicePopup) {
        addDevicePopup.style.display = "none";
    }
});

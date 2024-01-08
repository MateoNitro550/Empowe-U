// JavaScript to handle the edit device function
document.addEventListener('DOMContentLoaded', function () {
  const editDeviceButton = document.getElementById('editDeviceButton');
  const deleteDeviceButton = document.getElementById('deleteDeviceButton');
  const moveToStockButton = document.getElementById('moveToStockButton');
  const saveChangesButton = document.getElementById('saveChangesButton');
  const rows = document.querySelectorAll('table tbody tr');
  const devicePopup = document.getElementById('deviceInfoPopup');

  let editModeActive = false;
  let selectedRow = null;

  const column_mapping = {
    'name': 'Device Name',
    'snid': 'SNID',
    'tag': 'Tag',
    'model': 'Model',
    'department': 'Department',
    'user': 'User',
    'assigned_to': 'Assigned To',
    'ip_address': 'IP Address',
    'mobile_number': 'Mobile Number',
    'category': 'Category',
    'status': 'Status',
    'comments': 'Comments'
  };

  editDeviceButton.addEventListener('click', () => {
    editModeActive = !editModeActive;

    if (editModeActive) {
      editDeviceButton.classList.add('edit-mode');
      rows.forEach((row) => {
        row.classList.add('edit-mode');
      });
      devicePopup.style.display = 'none';
    } else {
      editDeviceButton.classList.remove('edit-mode');
      rows.forEach((row) => {
        row.classList.remove('edit-mode');
      });
      devicePopup.style.display = 'none';
    }
  });

  rows.forEach((row) => {
    row.addEventListener('click', () => {
      if (editModeActive) {

        const deviceId = row.getAttribute('data-device-id');

        const currentCategory = window.location.pathname.split('/').pop();

        fetch(`/get_columns/${currentCategory}`)
          .then(response => response.json())
          .then(data => {

            const deviceInfo = Array.from(row.querySelectorAll('td')).map(td => td.textContent.trim());

            const hasSNIDColumn = data.columns.includes('snid');

            const formFields = data.columns.slice(1).map((column, index) => {
              const columnName = column_mapping[column] || column;
              const columnValue = deviceInfo[index];
              return `
                <label for="${columnName}">${columnName}:</label>
                <input type="text" id="${columnName}" name="${columnName}" value="${columnValue}" required>
                <br>
              `;
            }).join('');

            const buttonsHtml = `
              <button type="submit" id="saveChangesButton">Save Changes</button>
              <button type="button" id="deleteDeviceButton">Delete Device</button>
              <button type="button" id="moveToStockButton">Move to Stock</button>
            `;

            document.getElementById("editDeviceForm").innerHTML = formFields + buttonsHtml;

            selectedRow = row;
            devicePopup.style.display = 'block';
          })
          .catch(error => console.error('Error fetching data:', error));
      }
    });
  });

  document.getElementById('editDeviceForm').addEventListener('submit', (event) => {
    event.preventDefault();

    const updatedDevice = {
      id: selectedRow.getAttribute('data-device-id'),
      category: window.location.pathname.split('/').pop(),
    };

    const columns = document.getElementById("editDeviceForm").querySelectorAll('input[type="text"]');
    columns.forEach(column => {
      const columnName = column.getAttribute('name');

      const originalColumnName = Object.keys(column_mapping).find(key => column_mapping[key] === columnName);
      updatedDevice[originalColumnName || columnName] = column.value;

    });

    fetch('/update_device', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(updatedDevice),
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        devicePopup.style.display = 'none';
        location.reload();
      } else {
        console.error(data.error);
        alert('Failed to save changes. Please try again.');
      }
    })
    .catch(error => console.error('Error:', error));
  });

  document.getElementById('editDeviceForm').addEventListener('click', (event) => {
    const target = event.target;

    if (target.matches('#deleteDeviceButton')) {
      const confirmDelete = confirm('Are you sure you want to delete this device?');
      if (confirmDelete) {
        const deviceId = selectedRow.getAttribute('data-device-id');
        const category = window.location.pathname.split('/').pop();
        deleteDevice(deviceId, category);
      }
    } else if (target.matches('#moveToStockButton')) {
      const confirmMoveToStock = confirm('Are you sure you want to move this device to stock?');
      if (confirmMoveToStock) {
        const deviceId = selectedRow.getAttribute('data-device-id');
        const category = window.location.pathname.split('/').pop();
        const deviceInfo = Array.from(selectedRow.querySelectorAll('td')).map(td => td.textContent.trim());

        moveToStock(deviceInfo);
        deleteDevice(deviceId, category);
      }
    }
  });

  function deleteDevice(deviceId, category) {
    const dataToDelete = {
      id: deviceId,
      category: category,
    };

    fetch('/delete_device', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(dataToDelete),
    })
    .then(response => response.json())
    .then(data => {
      if (data.success) {
        location.reload();
      } else {
        console.error(data.error);
        alert('Failed to delete the device. Please try again.');
      }
    })
    .catch(error => console.error('Error:', error));
  }

  function moveToStock(deviceInfo) {
      const dataToMove = {
          deviceInfo: {},
      };

      const currentCategory = window.location.pathname.split('/').pop();
      fetch(`/get_columns/${currentCategory}`)
          .then(response => response.json())
          .then(data => {
              const columns = data.columns;

              columns.slice(1).forEach((column, index) => {
                  const columnName = column_mapping[column] || column;
                  dataToMove.deviceInfo[columnName] = deviceInfo[index];
              });

              fetch('/move_to_stock', {
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/json',
                  },
                  body: JSON.stringify(dataToMove),
              })
              .then(response => response.json())
              .then(data => {
                  if (data.success) {
                      location.reload();
                  } else {
                      console.error(data.error);
                      alert('Failed to move the device to stock. Please try again.');
                  }
              })
              .catch(error => console.error('Error:', error));
          })
          .catch(error => console.error('Error fetching data:', error));
  }

  closeDeviceInfoPopup.addEventListener('click', () => {
    devicePopup.style.display = 'none';
  });

  window.addEventListener('click', (event) => {
    if (event.target === devicePopup) {
      devicePopup.style.display = 'none';
    }
  });
});

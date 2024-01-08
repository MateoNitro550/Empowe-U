// JavaScript to handle the real-time search
const searchInput = document.getElementById('searchInput');
const noResultsMessage = document.getElementById('noResultsMessage');
let inputHistory = [];
let redoHistory = [];

function applySearch() {
  const searchTerm = searchInput.value.toLowerCase();

  const rows = document.querySelectorAll('table tbody tr');
  let hasResults = false;

  rows.forEach((row) => {
    const cellText = row.textContent.toLowerCase();

    const isMatchingSearch = cellText.includes(searchTerm);

    if (isMatchingSearch) {
      row.style.display = 'table-row';
      hasResults = true;
    } else {
      row.style.display = 'none';
    }
  });

  noResultsMessage.style.display = hasResults ? 'none' : 'block';
}

document.addEventListener('keydown', (event) => {
  const isPrintable = event.key.length === 1;

  if (event.target.tagName.toLowerCase() === 'input') {
    return;
  }

  if (event.ctrlKey && event.key === 'z') {
    event.preventDefault();
    undo();
  } else if (event.ctrlKey && event.key === 'y') {
    event.preventDefault();
    redo();
  } else if (event.ctrlKey && event.key === 'v') {
    searchInput.focus();
    setTimeout(() => {
      applySearch();
    }, 0);
  } else if (event.ctrlKey && isPrintable) {
    return;
  } else if (isPrintable) {
    event.preventDefault();
    const cursorStart = searchInput.selectionStart;
    const cursorEnd = searchInput.selectionEnd;
    const inputValue = searchInput.value;
    const newState = inputValue.substring(0, cursorStart) + event.key + inputValue.substring(cursorEnd);
    saveState(inputValue);
    searchInput.value = newState;
    searchInput.setSelectionRange(cursorStart + 1, cursorStart + 1);
    applySearch();
  } else if (event.key === 'Backspace') {
    event.preventDefault();
    deleteAction(true);
  } else if (event.key === 'Delete') {
    event.preventDefault();
    deleteAction(false);
  }
});

searchInput.addEventListener('paste', (event) => {
  event.preventDefault();
  const cursorStart = searchInput.selectionStart;
  const cursorEnd = searchInput.selectionEnd;
  const pastedText = (event.clipboardData || window.clipboardData).getData('text');
  const newState = searchInput.value.substring(0, cursorStart) + pastedText + searchInput.value.substring(cursorEnd);
  saveState(searchInput.value);
  searchInput.value = newState;
  searchInput.setSelectionRange(cursorStart + pastedText.length, cursorStart + pastedText.length);
  applySearch();
});

function saveState(state) {
  inputHistory.push(state);
  redoHistory = [];
}

function undo() {
  if (inputHistory.length > 0) {
    const currentState = searchInput.value;
    redoHistory.push(currentState);
    const previousState = inputHistory.pop();
    searchInput.value = previousState;
    applySearch();
  }
}

function redo() {
  if (redoHistory.length > 0) {
    const currentState = searchInput.value;
    inputHistory.push(currentState);
    const nextState = redoHistory.pop();
    searchInput.value = nextState;
    applySearch();
  }
}

function deleteAction(backspace) {
  const cursorStart = searchInput.selectionStart;
  const cursorEnd = searchInput.selectionEnd;
  const inputValue = searchInput.value;

  if (cursorStart !== cursorEnd) {
    const newState = inputValue.substring(0, cursorStart) + inputValue.substring(cursorEnd);
    saveState(inputValue);
    searchInput.value = newState;
    searchInput.setSelectionRange(cursorStart, cursorStart);
  } else {
    const newState = backspace
      ? inputValue.substring(0, cursorStart - 1) + inputValue.substring(cursorStart)
      : inputValue.substring(0, cursorStart) + inputValue.substring(cursorStart + 1);
    saveState(inputValue);
    searchInput.value = newState;
    searchInput.setSelectionRange(cursorStart, cursorStart);
  }

  applySearch();
}

applySearch();

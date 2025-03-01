// // Initialize button with user's preferred color
// let changeColor = document.getElementById("changeColor");

// chrome.storage.sync.get("color", ({ color }) => {
//   changeColor.style.backgroundColor = color;
// });
chrome.storage.local.get('key', function(result) {
  console.log('Current news content:', result.key);
  // You can add any additional functionality for the popup here
});

document.addEventListener('DOMContentLoaded', function() {
  chrome.storage.local.get(['isFakeNews'], function(result) {
    console.log('Current news content:', result.key);
    if (result.isFakeNews === undefined) {
      showDefault();
    } else if (result.isFakeNews) {
      showFake();
    } else {
      showGenuine();
    }
  });
});

function showLoading() {
  document.getElementById('loading_div').classList.remove('hidden');
  document.getElementById('genuine_div').classList.add('hidden');
  document.getElementById('fake_div').classList.add('hidden');
  document.getElementById('default_div').classList.add('hidden');
}

function showGenuine() {
  document.getElementById('loading_div').classList.add('hidden');
  document.getElementById('genuine_div').classList.remove('hidden');
  document.getElementById('fake_div').classList.add('hidden');
  document.getElementById('default_div').classList.add('hidden');
}

function showFake() {
  document.getElementById('loading_div').classList.add('hidden');
  document.getElementById('genuine_div').classList.add('hidden');
  document.getElementById('fake_div').classList.remove('hidden');
  document.getElementById('default_div').classList.add('hidden');
}

function showDefault() {
  document.getElementById('loading_div').classList.add('hidden');
  document.getElementById('genuine_div').classList.add('hidden');
  document.getElementById('fake_div').classList.add('hidden');
  document.getElementById('default_div').classList.remove('hidden');
}

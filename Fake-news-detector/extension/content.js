console.log('Content script loaded');

const styles = `
  @import url('https://fonts.googleapis.com/css2?family=Roboto:wght@400;700&display=swap');
  .fake-news-overlay, .genuine-popup, .warning-modal {
    font-family: 'Roboto', sans-serif;
    position: fixed;
    z-index: 9999;
  }
  .fake-news-overlay {
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background-color: rgba(255, 0, 0, 0.9);
    color: white;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    font-size: 24px;
    backdrop-filter: blur(10px);
  }
  .close-button {
    position: absolute;
    top: 20px;
    right: 20px;
    font-size: 30px;
    color: white;
    cursor: pointer;
    background: none;
    border: none;
  }
  .genuine-popup {
    top: 20px;
    right: 20px;
    background-color: #4CAF50;
    color: white;
    padding: 15px;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
  }
  .warning-modal {
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    background-color: white;
    padding: 20px;
    border-radius: 8px;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    text-align: center;
    z-index: 10000;
  }
  .warning-modal h2 {
    color: #FF4136;
    margin-top: 0;
  }
  .warning-modal p {
    margin-bottom: 20px;
  }
  .warning-modal button {
    background-color: #FF4136;
    color: white;
    border: none;
    padding: 10px 20px;
    border-radius: 5px;
    cursor: pointer;
    font-size: 16px;
  }
`;

function addStyles() {
  const styleElement = document.createElement('style');
  styleElement.textContent = styles;
  document.head.appendChild(styleElement);
}

function showWarningModal() {
  const modal = document.createElement('div');
  modal.className = 'warning-modal';
  modal.innerHTML = `
    <h2>Warning: Potential Fake News</h2>
    <p>This article may contain misleading or false information. Please proceed with caution and verify the content from reliable sources.</p>
    <button id="continue-anyway">Continue Anyway</button>
  `;
  document.body.appendChild(modal);
  document.getElementById('continue-anyway').addEventListener('click', () => {
    modal.remove();
    document.querySelector('.fake-news-overlay').remove();
    document.body.style.overflow = 'auto';
  });
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  console.log('Message received in content script:', request);

  if (request.message === "get_news_content") {
    console.log('Attempting to get news content');
    const newsElement = document.querySelector('h1');
    if (newsElement) {
      const content = newsElement.textContent.trim();
      console.log('News content found:', content);
      sendResponse({ newsContent: content });
    } else {
      console.log('No news content found (h1 element not present)');
      sendResponse({ newsContent: null });
    }
  } else if (request.message === "show_fake_warning") {
    console.log('Showing fake news warning');
    addStyles();
    const overlay = document.createElement('div');
    overlay.className = 'fake-news-overlay';
    overlay.innerHTML = `
      <div>WARNING: This article may contain fake news.</div>
      <button class="close-button">&times;</button>
    `;
    document.body.appendChild(overlay);
    document.body.style.overflow = 'hidden';
    overlay.querySelector('.close-button').addEventListener('click', () => {
      showWarningModal();
    });
    console.log('Fake news warning displayed');
  } else if (request.message === "show_genuine_popup") {
    console.log('Showing genuine article popup');
    addStyles();
    const popup = document.createElement('div');
    popup.className = 'genuine-popup';
    popup.innerHTML = `
      This article appears to be genuine.
      <button class="close-button">&times;</button>
    `;
    document.body.appendChild(popup);
    popup.querySelector('.close-button').addEventListener('click', () => {
      console.log('Genuine article popup closed');
      popup.remove();
    });
    console.log('Genuine article popup displayed');
  } else {
    console.log('Unknown message received:', request.message);
  }
  return true;
});

console.log('Content script event listener set up complete');

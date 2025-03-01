// chrome.runtime.onInstalled.addListener(() => {
//     chrome.tabs.query({ active: true, }, function (tab) {
//       console.log(tab);
//         console.log(tab[0].title)
//         var input = tab[0].title;
//         chrome.tabs.sendMessage(tab[0].id, {"message": "got_title"});
//         console.log('sent message');
//         tabId = tab[0].id;
//         chrome.tabs.sendMessage(tabId, {"message": "send_message"});
//     });
// });


chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete') {
    chrome.tabs.sendMessage(tabId, { message: "get_news_content" }, (response) => {
      if (chrome.runtime.lastError) {
        console.log('Runtime error:', chrome.runtime.lastError);
        return;
      }
      if (response && response.newsContent) {
        console.log('News content found:', response.newsContent);
        sendToModel(response.newsContent, tabId);
      }
    });
  }
});

function sendToModel(content, tabId) {
  console.log('Sending content to model:', content);
  fetch("http://127.0.0.1:5005/predict", {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({text: [content]}),
  })
  .then(response => response.json())
  .then(data => {
    console.log('Prediction received:', data);
    if (data.prediction == 1) {
      chrome.storage.local.set({isFakeNews: false}, () => {
        console.log('Genuine content detected');
      });
      chrome.tabs.sendMessage(tabId, { message: "show_genuine_popup" });
    } else {
      chrome.storage.local.set({isFakeNews: true}, () => {
        console.log('Fake news detected');
      });
      chrome.tabs.sendMessage(tabId, { message: "show_fake_warning" });
    }
  })
  .catch((error) => {
    console.error('Error:', error);
  });
}

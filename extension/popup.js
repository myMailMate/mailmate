document.getElementById('templates-btn').addEventListener('click', function () {
    chrome.tabs.create({ url: 'http://localhost:3000' });
});
document.getElementById('scheduled-btn').addEventListener('click', function () {
    chrome.tabs.create({ url: 'http://localhost:3000/scheduled' });
});
document.getElementById('sent-btn').addEventListener('click', function () {
    chrome.tabs.create({ url: 'http://localhost:3000/sent' });
});

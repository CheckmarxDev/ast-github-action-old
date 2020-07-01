const { URL } = require('url');

function wrapError(e, message) {
    e.message = `${message}: ${e.message}`;
    return e;
}

function joinURLs(baseURL, path) {
    return new URL(path, baseURL).toString();
}

function timeout(operation, time) {
    return Promise.race([
        new Promise((resolve, reject) => setTimeout(() => reject(new Error(`Timeout of ${time} ms exceeded`)), time)),
        operation(),
    ]);
}

function sleep(time) {
    return new Promise((resolve) => setTimeout(resolve, time));
}

async function handleResponse(res) {
    if (!res.ok) {
        throw new Error(`Unexpected response from ${res.url}: ${res.status} ${await res.text()}`);
    }

    return res.json();
}

module.exports = {
    wrapError,
    joinURLs,
    timeout,
    handleResponse,
    sleep
};

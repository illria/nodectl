// Exercise the real subscription modal, including inline event handlers.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const {JSDOM} = require(process.env.NODECTL_UI_TEST_MODULES
    ? path.join(process.env.NODECTL_UI_TEST_MODULES, 'jsdom') : 'jsdom');
const html = fs.readFileSync(path.join(__dirname, '../templates/components/sub_links_modal.html'), 'utf8');
const flush = () => new Promise(resolve => setTimeout(resolve, 10));

async function checkModal(width) {
    const inspections = [], errors = [];
    let copied = '', qr = '';
    const dom = new JSDOM(html, {
        url: 'https://panel.example/', runScripts: 'dangerously', pretendToBeVisual: true,
        beforeParse(window) {
            Object.defineProperty(window, 'innerWidth', {value: width});
            Object.defineProperty(window, 'isSecureContext', {value: true});
            Object.defineProperty(window.navigator, 'clipboard', {
                value: {writeText: async text => {copied = text;}}
            });
            window.HTMLElement.prototype.scrollIntoView = function() {};
            window.QRCode = class { constructor(element, options) {qr = options.text;} };
            window.QRCode.CorrectLevel = {M: 0};
            window.addEventListener('error', event => errors.push(event.message));
            window.fetch = async (url, options) => {
                if (url === '/api/get-settings') {
                    return {ok: true, json: async () => ({status: 'success', data: {
                        sub_token: 'test&token', panel_url: 'https://panel.example/', sub_custom_name: '测试订阅'
                    }})};
                }
                const request = new URL(url);
                assert.equal(request.pathname, '/sub/singbox');
                assert.equal(request.searchParams.get('inspect'), '1');
                assert.equal(options.cache, 'no-store');
                inspections.push(request);
                return {ok: true, text: async () => JSON.stringify({
                    skipped_nodes: request.searchParams.get('version') === '1.8' ? ['AnyTLS: 需要 1.12+'] : []
                })};
            };
        }
    });
    const window = dom.window, document = window.document;
    const choose = (id, value) => {
        const select = document.getElementById(id);
        assert(select, id);
        select.value = value;
        select.dispatchEvent(new window.Event('change'));
    };
    const format = name => {
        const card = document.querySelector(`#wrap_${name} .sub-format-card`);
        if (!card.classList.contains('active')) card.click();
    };
    const checkLink = (name, topology) => {
        const text = document.getElementById('currentSubLinkText').value;
        const link = new URL(text);
        assert.equal(link.pathname, '/sub/' + name);
        assert.equal(link.searchParams.get('token'), 'test&token');
        assert.equal(link.searchParams.get('topology'), topology === 'single' ? 'single' : null);
        assert.equal(qr, text, 'QR points to another subscription');
        if (name === 'clash') {
            const imported = new URL(document.querySelector('.btn-import').href);
            assert.equal(imported.searchParams.get('url'), text);
            assert.equal(imported.searchParams.get('name'), '测试订阅');
        }
        if (width <= 768) assert.equal(document.getElementById('subRightCol').parentNode.id, 'wrap_' + name);
        return text;
    };
    try {
        await window.openSubLinksModal();
        for (const name of ['clash', 'v2ray', 'singbox']) {
            format(name);
            for (const topology of ['single', 'chain', 'single']) {
                choose('subTopologyChoice', topology);
                await flush();
                const text = checkLink(name, topology);
                document.getElementById('btnCopySubLink').click();
                await flush();
                assert.equal(copied, text, 'Copy uses an old subscription');
                if (name === 'singbox') {
                    const inspected = inspections.at(-1);
                    assert.equal(inspected.searchParams.get('topology'), topology === 'single' ? 'single' : null);
                }
            }
        }
        for (const version of ['1.8', '1.9', '1.10', '1.11', '1.12', '1.13', '1.14']) {
            choose('singBoxVersion', version);
            for (const mode of ['outbounds', 'full', 'mobile']) {
                choose('singBoxMode', mode);
                for (const topology of ['chain', 'single']) {
                    choose('subTopologyChoice', topology);
                    await flush();
                    const link = new URL(checkLink('singbox', topology));
                    assert.equal(link.searchParams.get('version'), version);
                    assert.equal(link.searchParams.get('mode'), mode);
                    assert.equal(document.getElementById('singBoxVersion').value, version);
                    assert.equal(document.getElementById('singBoxMode').value, mode);
                    const inspected = inspections.at(-1);
                    for (const key of ['version', 'mode', 'topology', 'token']) {
                        assert.equal(inspected.searchParams.get(key), link.searchParams.get(key));
                    }
                    const status = document.getElementById('singBoxCompatibility').textContent;
                    assert(status.includes(version === '1.8' ? 'AnyTLS' : '检查通过'), status);
                    assert.equal(!!document.querySelector('#subRightContent [role="alert"]'), mode === 'outbounds');
                }
            }
        }
        format('v2ray');
        assert(document.getElementById('subRightContent').textContent.includes('无法携带策略组'));
        await window.openSubLinksModal();
        checkLink('clash', 'single');
        assert.deepEqual(errors, [], 'Inline UI event failed');
        console.log(`${width}px: topology, all formats, version/mode, copy/QR/import, inspect and mobile placement passed`);
    } finally {
        window.close();
    }
}

(async () => { for (const width of [1280, 390]) await checkModal(width); })()
    .catch(error => {console.error(error); process.exit(1);});

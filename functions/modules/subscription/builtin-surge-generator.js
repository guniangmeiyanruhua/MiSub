/**
 * 内置 Surge 配置生成器
 * 不依赖外部 SubConverter，直接将节点 URL 转换为 Surge 配置
 * 解决 SubConverter 不支持 hysteria2 → Surge 转换的问题
 */

import { urlToClashProxy } from '../../utils/url-to-clash.js';

/**
 * 将 Clash 代理对象转换为 Surge [Proxy] 行
 * @param {Object} proxy - Clash 格式代理对象
 * @returns {string|null} Surge 代理行
 */
function clashProxyToSurgeLine(proxy) {
    if (!proxy || !proxy.server || !proxy.port) return null;

    const name = proxy.name || 'Untitled';
    const type = (proxy.type || '').toLowerCase();
    const server = proxy.server;
    const port = proxy.port;

    const parts = [];

    if (type === 'ss' || type === 'shadowsocks') {
        parts.push(`${name} = ss`);
        parts.push(server);
        parts.push(String(port));
        parts.push(`encrypt-method=${proxy.cipher || 'aes-128-gcm'}`);
        parts.push(`password=${proxy.password || ''}`);
        if (proxy.udp) parts.push('udp-relay=true');
    } else if (type === 'trojan') {
        parts.push(`${name} = trojan`);
        parts.push(server);
        parts.push(String(port));
        parts.push(`password=${proxy.password || ''}`);
        if (proxy.sni) parts.push(`sni=${proxy.sni}`);
        if (proxy['skip-cert-verify']) parts.push('skip-cert-verify=true');
        if (proxy.udp) parts.push('udp-relay=true');
        // WebSocket
        if (proxy.network === 'ws') {
            parts.push('ws=true');
            const wsOpts = proxy['ws-opts'] || proxy.wsOpts;
            if (wsOpts?.path) parts.push(`ws-path=${wsOpts.path}`);
            if (wsOpts?.headers?.Host) parts.push(`ws-headers=Host:${wsOpts.headers.Host}`);
        }
    } else if (type === 'vmess') {
        parts.push(`${name} = vmess`);
        parts.push(server);
        parts.push(String(port));
        parts.push(`username=${proxy.uuid || ''}`);
        if (proxy.tls) parts.push('tls=true');
        if (proxy.servername || proxy.sni) parts.push(`sni=${proxy.servername || proxy.sni}`);
        if (proxy['skip-cert-verify']) parts.push('skip-cert-verify=true');
        if (proxy.udp) parts.push('udp-relay=true');
        // WebSocket
        if (proxy.network === 'ws') {
            parts.push('ws=true');
            const wsOpts = proxy['ws-opts'] || proxy.wsOpts;
            if (wsOpts?.path) parts.push(`ws-path=${wsOpts.path}`);
            if (wsOpts?.headers?.Host) parts.push(`ws-headers=Host:${wsOpts.headers.Host}`);
        }
    } else if (type === 'hysteria2' || type === 'hy2') {
        parts.push(`${name} = hysteria2`);
        parts.push(server);
        parts.push(String(port));
        parts.push(`password=${proxy.password || ''}`);
        if (proxy.sni) parts.push(`sni=${proxy.sni}`);
        if (proxy['skip-cert-verify']) parts.push('skip-cert-verify=true');
        if (proxy.udp !== false) parts.push('udp-relay=true');
        // 下载/上传带宽限制
        if (proxy['down']) parts.push(`download-bandwidth=${proxy['down']}`);
    } else if (type === 'tuic') {
        parts.push(`${name} = tuic`);
        parts.push(server);
        parts.push(String(port));
        parts.push(`token=${proxy.token || proxy.password || ''}`);
        if (proxy.sni) parts.push(`sni=${proxy.sni}`);
        if (proxy['skip-cert-verify']) parts.push('skip-cert-verify=true');
        if (proxy.udp) parts.push('udp-relay=true');
    } else if (type === 'snell') {
        parts.push(`${name} = snell`);
        parts.push(server);
        parts.push(String(port));
        parts.push(`psk=${proxy.psk || proxy.password || ''}`);
        if (proxy.version) parts.push(`version=${proxy.version}`);
        const obfsOpts = proxy['obfs-opts'];
        if (obfsOpts) {
            if (obfsOpts.mode) parts.push(`obfs=${obfsOpts.mode}`);
            if (obfsOpts.host) parts.push(`obfs-host=${obfsOpts.host}`);
        }
        if (proxy.udp) parts.push('udp-relay=true');
    } else if (type === 'vless') {
        // Surge 不原生支持 VLESS，但 Surge 5.8+ 实际上通过插件或新版本可以
        // 这里生成一个兼容格式便于最大化保留
        // 注意：如果 Surge 版本不支持 VLESS，该节点会被忽略
        parts.push(`${name} = vless`);
        parts.push(server);
        parts.push(String(port));
        parts.push(`username=${proxy.uuid || ''}`);
        if (proxy.tls) parts.push('tls=true');
        if (proxy.servername || proxy.sni) parts.push(`sni=${proxy.servername || proxy.sni}`);
        if (proxy.flow) parts.push(`flow=${proxy.flow}`);
        if (proxy['skip-cert-verify']) parts.push('skip-cert-verify=true');
        if (proxy.udp) parts.push('udp-relay=true');
        // Reality
        const realityOpts = proxy['reality-opts'];
        if (realityOpts) {
            if (realityOpts['public-key']) parts.push(`server-cert-fingerprint-sha256=${realityOpts['public-key']}`);
        }
        // Fingerprint
        if (proxy['client-fingerprint']) parts.push(`client-fingerprint=${proxy['client-fingerprint']}`);
    } else if (type === 'http' || type === 'https') {
        parts.push(`${name} = ${type}`);
        parts.push(server);
        parts.push(String(port));
        if (proxy.username) parts.push(`username=${proxy.username}`);
        if (proxy.password) parts.push(`password=${proxy.password}`);
    } else if (type === 'socks5') {
        parts.push(`${name} = socks5`);
        parts.push(server);
        parts.push(String(port));
        if (proxy.username) parts.push(`username=${proxy.username}`);
        if (proxy.password) parts.push(`password=${proxy.password}`);
        if (proxy.udp) parts.push('udp-relay=true');
    } else {
        // 不支持的类型
        return null;
    }

    return parts.join(', ');
}

/**
 * 生成完整的内置 Surge 配置
 * @param {string} nodeList - 节点列表（换行分隔的 URL）
 * @param {Object} options - 配置选项
 * @returns {string} Surge INI 配置
 */
export function generateBuiltinSurgeConfig(nodeList, options = {}) {
    const {
        fileName = 'MiSub',
        managedConfigUrl = '',
        interval = 86400
    } = options;

    // 解析节点 URL 列表
    const nodeUrls = nodeList
        .split('\n')
        .map(line => line.trim())
        .filter(line => line && !line.startsWith('#'));

    // URL → Clash Proxy Object → Surge Line
    const proxyLines = [];
    const proxyNames = [];

    for (const url of nodeUrls) {
        const clashProxy = urlToClashProxy(url);
        if (!clashProxy) continue;

        const surgeLine = clashProxyToSurgeLine(clashProxy);
        if (surgeLine) {
            proxyLines.push(surgeLine);
            proxyNames.push(clashProxy.name);
        }
    }

    // 处理重名
    const usedNames = new Set();
    const finalProxyLines = [];
    const finalProxyNames = [];

    for (let i = 0; i < proxyLines.length; i++) {
        let name = proxyNames[i];
        if (usedNames.has(name)) {
            let j = 1;
            while (usedNames.has(`${name}_${j}`)) j++;
            const newName = `${name}_${j}`;
            // 替换行中的名称
            finalProxyLines.push(proxyLines[i].replace(name, newName));
            finalProxyNames.push(newName);
            usedNames.add(newName);
        } else {
            finalProxyLines.push(proxyLines[i]);
            finalProxyNames.push(name);
            usedNames.add(name);
        }
    }

    if (finalProxyLines.length === 0) {
        return `[General]\nloglevel = notify\n\n[Proxy]\nDIRECT = direct\n\n[Proxy Group]\n\n[Rule]\nFINAL,DIRECT\n`;
    }

    // 构建 Surge 配置
    const sections = [];

    // [General]
    const managedLine = managedConfigUrl
        ? `#!MANAGED-CONFIG ${managedConfigUrl} interval=${interval} strict=false\n\n`
        : '';

    sections.push(`${managedLine}[General]
loglevel = notify
skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, localhost, *.local
dns-server = 119.29.29.29, 223.5.5.5, system`);

    // [Proxy]
    sections.push(`[Proxy]
DIRECT = direct
${finalProxyLines.join('\n')}`);

    // [Proxy Group]
    const proxyNamesList = finalProxyNames.join(', ');
    sections.push(`[Proxy Group]
📶 节点选择 = select, ♻️ 自动选择, ${proxyNamesList}, DIRECT
♻️ 自动选择 = url-test, ${proxyNamesList}, url=http://www.gstatic.com/generate_204, interval=300, tolerance=50`);

    // [Rule]
    sections.push(`[Rule]
GEOIP,CN,DIRECT
FINAL,📶 节点选择`);

    return sections.join('\n\n') + '\n';
}

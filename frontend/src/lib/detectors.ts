import type { DetectorKey, Severity } from './types';

interface DetectorMeta {
  key: DetectorKey;
  label: string;
  short: string;
  icon: string;
  color: string;
  plainEnglish: string;
  nextStep: string;
}

export const DETECTORS: Record<DetectorKey, DetectorMeta> = {
  arp_spoof: {
    key: 'arp_spoof',
    label: 'ARP Spoofing',
    short: 'ARP',
    icon: 'Network',
    color: '#F97316',
    plainEnglish:
      'An attacker is pretending to be another device on your network to intercept or alter traffic between you and the router.',
    nextStep: 'Identify the device sending conflicting ARP replies and disconnect it. Reboot your router to flush ARP caches.',
  },
  dns_spoof: {
    key: 'dns_spoof',
    label: 'DNS Spoofing',
    short: 'DNS',
    icon: 'Globe',
    color: '#F59E0B',
    plainEnglish:
      'Someone is redirecting website lookups to fake servers, so you may be sent to impostor websites even when you type the correct address.',
    nextStep: 'Flush your DNS cache and set your devices to use a trusted DNS resolver like 1.1.1.1 or 8.8.8.8.',
  },
  rogue_access: {
    key: 'rogue_access',
    label: 'Rogue Access Point',
    short: 'Rogue AP',
    icon: 'Wifi',
    color: '#EF4444',
    plainEnglish:
      'A fake Wi-Fi network is mimicking a trusted network name to lure devices into connecting to it so traffic can be monitored.',
    nextStep: 'Forget the suspicious network from your devices and connect only to the known-good access point. Check for unknown hardware nearby.',
  },
  ssl_strip: {
    key: 'ssl_strip',
    label: 'SSL Stripping',
    short: 'SSL',
    icon: 'Lock',
    color: '#EF4444',
    plainEnglish:
      'A secure HTTPS connection was silently downgraded to unencrypted HTTP, meaning someone may be able to read your "secure" traffic.',
    nextStep: 'Avoid entering passwords on the affected site until the connection is verified. Enable HSTS in your browser if available.',
  },
  http_inject: {
    key: 'http_inject',
    label: 'HTTP Injection',
    short: 'HTTP',
    icon: 'FileCode2',
    color: '#F97316',
    plainEnglish:
      'Extra content or scripts were injected into an unencrypted webpage you loaded — often used to show fake login boxes or ads.',
    nextStep: 'Stop browsing on the affected network. Clear browser cache and cookies, and run a malware scan on affected devices.',
  },
  icmp_redirect: {
    key: 'icmp_redirect',
    label: 'ICMP Redirect',
    short: 'ICMP',
    icon: 'Route',
    color: '#F59E0B',
    plainEnglish:
      'An attacker is telling your device to send traffic through a different path, so they can intercept it.',
    nextStep: 'Disable ICMP redirect acceptance on your devices and verify your router is the only default gateway.',
  },
  dhcp_spoof: {
    key: 'dhcp_spoof',
    label: 'DHCP Spoofing',
    short: 'DHCP',
    icon: 'Server',
    color: '#F97316',
    plainEnglish:
      'A rogue server is handing out fake network settings, redirecting your traffic through an attacker-controlled gateway.',
    nextStep: 'Set static DNS and gateway on critical devices, and disable rogue DHCP servers on your network.',
  },
};

export const SEVERITY_META: Record<
  Severity,
  { label: string; color: string; bg: string; text: string; border: string }
> = {
  critical: { label: 'Critical', color: '#EF4444', bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/40' },
  high: { label: 'High', color: '#F97316', bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/40' },
  medium: { label: 'Medium', color: '#F59E0B', bg: 'bg-amber-500/15', text: 'text-amber-400', border: 'border-amber-500/40' },
  low: { label: 'Low', color: '#3B82F6', bg: 'bg-blue-500/15', text: 'text-blue-400', border: 'border-blue-500/40' },
  info: { label: 'Info', color: '#22C55E', bg: 'bg-green-500/15', text: 'text-green-400', border: 'border-green-500/40' },
};

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function detectorMeta(key: DetectorKey) {
  return DETECTORS[key];
}

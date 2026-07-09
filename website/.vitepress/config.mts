import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'LianYaoHu',
  description:
    'Run code agents inside a constrained sandbox, forced through a selected VPN interface.',
  base: '/',
  cleanUrls: true,
  themeConfig: {
    nav: [
      { text: 'Guide', link: '/guide' },
      { text: 'Architecture', link: '/architecture' },
      { text: 'Security Model', link: '/security-model' },
    ],
    sidebar: [
      {
        text: 'Documentation',
        items: [
          { text: 'Getting Started', link: '/guide' },
          { text: 'Architecture', link: '/architecture' },
          { text: 'Security Model', link: '/security-model' },
          { text: 'End-to-End Testing', link: '/e2e-testing' },
        ],
      },
    ],
    socialLinks: [{ icon: 'github', link: 'https://github.com/madeye/LianYaoHu' }],
    search: { provider: 'local' },
    outline: 'deep',
    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2026 Max Lv',
    },
  },
})

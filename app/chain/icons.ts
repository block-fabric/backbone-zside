// Icons of zSide's own pages (components/Icon.svelte): line icons on a 24 grid, one SVG path each.
export const LOCAL_ICONS = {
  /** Private: a shield with a keyhole. */
  private: 'M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6zM12 10.5a1.6 1.6 0 1 0 0 .01M12 12v3.5',
  /** Memos: a sealed envelope. */
  memo: 'M4 6h16v12H4zM4 7l8 6 8-6M9 13.5L4 18M15 13.5l5 4.5',
  /** The shielded pool: a drop over waves. */
  pool: 'M12 3c2.5 3 4 5.2 4 7a4 4 0 0 1-8 0c0-1.8 1.5-4 4-7zM3 17c3 2 6 2 9 0s6-2 9 0M3 21c3 2 6 2 9 0s6-2 9 0',
  /** Shield: coins going down into the pool. */
  shieldin: 'M12 3v9M8.5 8.5L12 12l3.5-3.5M4 15c2.7 1.8 5.3 1.8 8 0s5.3-1.8 8 0M4 19c2.7 1.8 5.3 1.8 8 0s5.3-1.8 8 0',
  /** Unshield: coins coming up out of the pool. */
  shieldout: 'M12 12V3M8.5 6.5L12 3l3.5 3.5M4 15c2.7 1.8 5.3 1.8 8 0s5.3-1.8 8 0M4 19c2.7 1.8 5.3 1.8 8 0s5.3-1.8 8 0',
} as const satisfies Record<string, string>;

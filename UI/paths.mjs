import { homedir } from 'node:os';
import { resolve } from 'node:path';

export const installedUiDir = resolve(homedir(), 'Library/Application Support/ActivityObserver UI/UI');
export const installedReviewDir = resolve(installedUiDir, 'dist');
export const observerPort = 47652;
export const observerUrl = `http://127.0.0.1:${observerPort}/mcp`;

// Runs before every test file: removes the file's temporary data directories when it is done.
import { afterAll } from 'vitest';
import { cleanupTmp } from './fixture.js';

afterAll(() => cleanupTmp());

import { defineBackend } from '@aws-amplify/backend';
import { myFirstFunction } from './my-first-function/resource';

/**
 * @see https://docs.amplify.aws/gen2/build-a-backend/
 */
defineBackend({
  myFirstFunction,
});

// Increase timeout for integration tests that hit real DB
jest.setTimeout(30000);

// Clean up after all tests in a file complete
afterAll(async () => {
  // Small delay to let async operations settle
  await new Promise((resolve) => setTimeout(resolve, 500));
});

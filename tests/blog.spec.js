const { test, expect } = require('@playwright/test');

test('Register and login', async ({ page }) => {
  // Go to register page
  await page.goto('/register');

  const username = 'testuser' + Date.now();
  const password = 'Password123!';

  // Fill registration form
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="email"]', username + '@example.com');
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');

  // After register, we expect to land on login page
  await page.waitForURL('**/login');

  // Fill login form
  await page.fill('input[name="username"]', username);
  await page.fill('input[name="password"]', password);
  await page.click('button[type="submit"]');

  // Expect redirect to posts page
  await page.waitForURL('**/posts**');

  // We are on posts page
  await expect(page).toHaveURL(/.*posts.*/);
});

# Page snapshot

```yaml
- generic [active]:
  - banner:
    - heading "Secure Blog" [level=1]
    - link "Login" [ref=e1]:
      - /url: /login
    - text: "|"
    - link "Register" [ref=e2]:
      - /url: /register
    - separator [ref=e3]
  - heading "Register" [level=2]
  - generic:
    - generic:
      - text: "Username:"
      - textbox [ref=e4]: testuser1764955580350
    - generic:
      - text: "Email:"
      - textbox [ref=e5]: testuser1764955580350@example.com
    - generic:
      - text: "Password:"
      - textbox [ref=e6]: Password123!
    - button "Register" [ref=e7]
```
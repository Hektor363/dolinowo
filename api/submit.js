
export default {
  async fetch(request) {
    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { "Content-Type": "application/json" }
      });

    if (request.method !== "POST") {
      return json({ error: "Method not allowed" }, 405);
    }

    const origin = request.headers.get("origin");
    const allowedOrigins = [
      "https://dolinowo.pl",
      "https://www.dolinowo.pl"
    ];

    if (!origin || !allowedOrigins.includes(origin)) {
      return json({ error: "Forbidden" }, 403);
    }

    try {
      const form = await request.formData();

      // Honeypot
      if (form.get("_gotcha")) {
        return json({ success: true });
      }

      const name = String(form.get("name") || "").trim();
      const email = String(form.get("email") || "").trim();
      const message = String(form.get("message") || "").trim();
      const token = String(
        form.get("cf-turnstile-response") || ""
      );

      if (!name || !email || !token) {
        return json({ error: "Uzupełnij wymagane pola." }, 400);
      }

      if (name.length > 100 || email.length > 254 ||
          message.length > 3000) {
        return json({ error: "Zbyt długie dane." }, 400);
      }

      // Verify Cloudflare Turnstile
      const verification = new FormData();
      verification.append(
        "secret",
        process.env.TURNSTILE_SECRET_KEY
      );
      verification.append("response", token);

      const ip = request.headers.get("x-forwarded-for")
        ?.split(",")[0]?.trim();

      if (ip) verification.append("remoteip", ip);

      const captchaResponse = await fetch(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify",
        {
          method: "POST",
          body: verification
        }
      );

      const captcha = await captchaResponse.json();

      if (!captcha.success ||
          !["dolinowo.pl", "www.dolinowo.pl"].includes(captcha.hostname)) {
        return json({
          error: "Weryfikacja CAPTCHA nie powiodła się."
        }, 403);
      }

      // Forward only validated fields to Formspree
      const submission = new FormData();
      submission.append("name", name);
      submission.append("email", email);
      submission.append("message", message);
      submission.append("phone", String(form.get("phone") || ""));
      submission.append("from", String(form.get("from") || ""));
      submission.append("to", String(form.get("to") || ""));

      const endpoint = process.env.FORMSPREE_ENDPOINT;

      const result = await fetch(endpoint, {
        method: "POST",
        body: submission,
        headers: { Accept: "application/json" }
      });

      if (!result.ok) {
        return json({
          error: "Nie udało się wysłać formularza. Spróbuj później."
        }, 502);
      }

      return json({ success: true });

    } catch (error) {
      return json({
        error: "Wystąpił błąd serwera."
      }, 500);
    }
  }
};

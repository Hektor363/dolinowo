export default async function handler(req, res) {
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");

  const send = (status, payload) => res.status(status).json(payload);

  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return send(405, { success: false, error: "Method not allowed" });
  }

  const allowedOrigins = new Set([
    "https://dolinowo.pl",
    "https://www.dolinowo.pl",
  ]);

  const origin = req.headers.origin;

  if (!origin || !allowedOrigins.has(origin)) {
    return send(403, { success: false, error: "Invalid origin" });
  }

  try {
    const secretKey = process.env.TURNSTILE_SECRET_KEY;
    const endpoint = process.env.FORMSPREE_ENDPOINT;

    if (!secretKey || !endpoint) {
      return send(500, {
        success: false,
        error: "Server configuration error",
      });
    }

    if (!/^https:\/\/formspree\.io\/f\/[A-Za-z0-9]+$/.test(endpoint)) {
      return send(500, {
        success: false,
        error: "Invalid Formspree endpoint",
      });
    }

    const body = req.body;

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return send(400, { success: false, error: "Invalid form data" });
    }

    // Honeypot – ukryte pole, które powinno pozostać puste.
    if (typeof body._gotcha === "string" && body._gotcha.trim() !== "") {
      return send(200, { success: true });
    }

    const name = String(body.name || "").trim();
    const email = String(body.email || "").trim();
    const message = String(body.message || "").trim();
    const phone = String(body.phone || "").trim();
    const from = String(body.from || "").trim();
    const to = String(body.to || "").trim();
    const token = String(body["cf-turnstile-response"] || "").trim();

    if (!name || !email || !token) {
      return send(400, {
        success: false,
        error: "Uzupełnij wymagane pola i CAPTCHA.",
      });
    }

    if (name.length > 120 || email.length > 254 || message.length > 5000) {
      return send(400, { success: false, error: "Za długie dane formularza." });
    }

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return send(400, { success: false, error: "Nieprawidłowy adres e-mail." });
    }

    if (from && to) {
      const startDate = new Date(from);
      const endDate = new Date(to);

      if (
        Number.isNaN(startDate.getTime()) ||
        Number.isNaN(endDate.getTime()) ||
        endDate <= startDate
      ) {
        return send(400, {
          success: false,
          error: "Nieprawidłowy zakres dat.",
        });
      }
    }

    // Weryfikacja CAPTCHA po stronie serwera.
    const captchaData = new URLSearchParams();
    captchaData.append("secret", secretKey);
    captchaData.append("response", token);

    const forwardedFor = req.headers["x-forwarded-for"];
    if (forwardedFor) {
      captchaData.append("remoteip", forwardedFor.split(",")[0].trim());
    }

    const captchaResponse = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
        body: captchaData,
      }
    );

    const captcha = await captchaResponse.json();

    if (
      !captcha.success ||
      !["dolinowo.pl", "www.dolinowo.pl"].includes(captcha.hostname)
    ) {
      return send(403, {
        success: false,
        error: "Weryfikacja CAPTCHA nie powiodła się. Spróbuj ponownie.",
      });
    }

    // Przekazanie zweryfikowanego zgłoszenia do Formspree.
    const formData = new FormData();

    formData.append("name", name);
    formData.append("email", email);
    formData.append("message", message);

    if (phone) formData.append("phone", phone);
    if (from) formData.append("from", from);
    if (to) formData.append("to", to);

    const formspreeResponse = await fetch(endpoint, {
      method: "POST",
      headers: {
        Accept: "application/json",
      },
      body: formData,
    });

    if (!formspreeResponse.ok) {
      return send(502, {
        success: false,
        error: "Nie udało się wysłać formularza. Spróbuj ponownie.",
      });
    }

    return send(200, { success: true });
  } catch (error) {
    console.error("Form submission error:", error);

    return send(500, {
      success: false,
      error: "Wystąpił błąd serwera.",
    });
  }
}

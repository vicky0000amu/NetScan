require("dotenv").config();

const express = require("express");
const rateLimit = require("express-rate-limit");
const path = require("path");
const { runScan, listProfiles } = require("./utils/nmapScanner");
const supabase = require("./config/supabase");

const app = express();
const PORT = process.env.PORT || 3000;

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ----------------------------------------------------------------------
// Rate Limiter
// ----------------------------------------------------------------------

const scanLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: {
    error: "Too many scans from this IP. Please wait a while and try again.",
  },
});

// ----------------------------------------------------------------------
// Home Page (Scanner)
// ----------------------------------------------------------------------

app.get("/", (req, res) => {
  res.render("index", {
    profiles: listProfiles(),
  });
});

// ----------------------------------------------------------------------
// Scan History
// ----------------------------------------------------------------------

app.get("/history", async (req, res) => {
  const { data: scans, error } = await supabase
    .from("scans")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) {
    return res.send(error.message);
  }

  res.render("history", {
    scans,
  });
});

// ----------------------------------------------------------------------
// Scan Details
// ----------------------------------------------------------------------

app.get("/history/:id", async (req, res) => {
  const scanId = req.params.id;

  const { data: scan, error: scanError } = await supabase
    .from("scans")
    .select("*")
    .eq("id", scanId)
    .single();

  if (scanError) {
    return res.send(scanError.message);
  }

  const { data: ports, error: portError } = await supabase
    .from("ports")
    .select("*")
    .eq("scan_id", scanId)
    .order("port");

  if (portError) {
    return res.send(portError.message);
  }

  res.render("scan-details", {
    scan,
    ports,
  });
});

// ----------------------------------------------------------------------
// Run Scan
// ----------------------------------------------------------------------

app.post("/scan", scanLimiter, async (req, res) => {
  const { target, profile, confirmAuthorized } = req.body;

  if (!confirmAuthorized) {
    return res.status(400).json({
      error: "You must confirm you are authorized to scan this target.",
    });
  }

  try {
    const result = await runScan(target, profile);

    const host = result.hosts[0];
    const ip = host.address;
    const hostname = host.hostname;
    const ports = host.ports;

    // --------------------------------------------------------------
    // Save Scan
    // --------------------------------------------------------------

    const { data: scanData, error: scanError } = await supabase
      .from("scans")
      .insert([
        {
          target,
          ip,
          hostname,
          profile,
          scan_status: "completed",
        },
      ])
      .select()
      .single();

    if (scanError) {
      console.log("❌ Scan Insert Error:");
      console.log(scanError);
    } else {
      console.log("✅ Scan Saved.");

      // ----------------------------------------------------------
      // Save Ports
      // ----------------------------------------------------------

      if (ports && ports.length > 0) {
        const portRows = ports.map((p) => ({
          scan_id: scanData.id,
          port: Number(p.port),
          protocol: p.protocol,
          state: p.state,
          service: p.service,
          version:
            p.product && p.version
              ? `${p.product} ${p.version}`
              : p.product || p.version || "",
        }));

        const { error: portError } = await supabase
          .from("ports")
          .insert(portRows);

        if (portError) {
          console.log("❌ Port Insert Error:");
          console.log(portError);
        } else {
          console.log("✅ Ports Saved.");
        }
      }
    }

    res.json({
      success: true,
      ...result,
    });

  } catch (err) {
    console.log(err);

    res.status(400).json({
      error: err.message,
    });
  }
});

// ----------------------------------------------------------------------
// Start Server
// ----------------------------------------------------------------------

app.listen(PORT, async () => {
  console.log(`NetScan running at http://localhost:${PORT}`);

  const { error } = await supabase
    .from("scans")
    .select("*")
    .limit(1);

  if (error) {
    console.log("❌ Supabase connection failed");
    console.log(error.message);
  } else {
    console.log("✅ Supabase connected successfully!");
  }
});
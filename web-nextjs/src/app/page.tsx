"use client";
import InputFileUpload, { ScanResult } from "@/components/file-upload";
import {
  Box,
  Container,
  Grid,
  List,
  ListItem,
  ListItemText,
  Paper,
  Typography,
  Alert,
  Accordion,
  AccordionSummary,
  AccordionDetails,
  LinearProgress,
} from "@mui/material";
import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import { Fragment, useEffect, useState } from "react";
// import * as rf_validator from "rf_validator";
export default function Home() {
  const [validator, setValidator] = useState<
    typeof import("@/rust/rf_validator") | null
  >(null);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function loadWasm() {
      try {
        const wasmModule = await import("@/rust/rf_validator");
        // await wasmModule.default(); // initialize wasm
        setValidator(wasmModule);
      } catch (err) {
        console.error("Failed to load WASM module:", err);
        setError("Failed to load scanner. Please try again later.");
      }
    }
    loadWasm();
  }, []);

  const handleScanComplete = (result: ScanResult | null) => {
    if (result) {
      setScanResult(result);
      setError(null);
    } else {
      setError("Failed to scan file. Please try again.");
    }
  };

  return (
    <Fragment>
      <Container maxWidth="md">
        <Paper elevation={3} sx={{ p: 4, mt: 4 }}>
          <Grid
            container
            direction="column"
            spacing={3}
            sx={{
              justifyContent: "center",
              alignItems: "center",
              textAlign: "center",
            }}
          >
            <Grid size={12}>
              <Typography variant="h4" component="h1" gutterBottom>
                Chinny's Scanner
              </Typography>
              <Typography variant="body1" color="text.secondary">
                Upload a file to scan it for potential threats
              </Typography>
            </Grid>

            <Grid size={12}>
              <InputFileUpload
                validator={validator}
                onScanComplete={handleScanComplete}
              />
            </Grid>

            {error && (
              <Grid size={12}>
                <Alert severity="error" sx={{ mt: 2 }}>
                  {error}
                </Alert>
              </Grid>
            )}

            {scanResult && (
              <Grid size={12} sx={{ width: "100%", mt: 2 }}>
                <Box sx={{ textAlign: "left", mt: 2, width: "100%" }}>
                  <Typography variant="h6">Scan Results</Typography>
                  <Typography variant="body2">
                    File type: {scanResult.fileType}
                  </Typography>
                  <Typography variant="body2" color="text.secondary">
                    Execution time: {scanResult.executionTimeSec.toFixed(3)}{" "}
                    seconds
                  </Typography>

                  <Alert
                    severity={
                      scanResult.result === "Clean" ? "success" : "warning"
                    }
                    sx={{ mt: 1 }}
                  >
                    {scanResult.result === "Clean"
                      ? "No threats detected"
                      : "Potential threats detected"}
                  </Alert>

                  {scanResult.findings.length > 0 && (
                    <Box sx={{ mt: 2 }}>
                      <Typography variant="subtitle1">Findings:</Typography>
                      <List dense>
                        {scanResult.findings.map((finding, index) => (
                          <ListItem
                            key={index}
                            divider={index < scanResult.findings.length - 1}
                          >
                            <ListItemText primary={finding} />
                          </ListItem>
                        ))}
                      </List>
                    </Box>
                  )}

                  {scanResult.stepTimings &&
                    scanResult.stepTimings.length > 0 && (
                      <Accordion sx={{ mt: 2 }}>
                        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                          <Typography variant="subtitle1">
                            Step-by-Step Execution Times
                          </Typography>
                        </AccordionSummary>
                        <AccordionDetails>
                          {(() => {
                            const maxTimeMs = Math.max(
                              ...scanResult.stepTimings!.map((t) => t.timeMs)
                            );
                            return (
                              <Box sx={{ width: "100%" }}>
                                {scanResult.stepTimings!.map(
                                  (timing, index) => (
                                    <Box key={index} sx={{ mb: 1 }}>
                                      <Typography
                                        variant="body2"
                                        component="div"
                                        sx={{
                                          display: "flex",
                                          justifyContent: "space-between",
                                        }}
                                      >
                                        <span>{timing.label}</span>
                                        <span>
                                          {timing.timeMs.toFixed(2)}ms
                                        </span>
                                      </Typography>
                                      <LinearProgress
                                        variant="determinate"
                                        value={
                                          (timing.timeMs / maxTimeMs) * 100
                                        }
                                        sx={{
                                          height: 8,
                                          borderRadius: 1,
                                          bgcolor: "rgba(0,0,0,0.05)",
                                        }}
                                      />
                                    </Box>
                                  )
                                )}
                              </Box>
                            );
                          })()}
                        </AccordionDetails>
                      </Accordion>
                    )}
                </Box>
              </Grid>
            )}
          </Grid>
        </Paper>
      </Container>
    </Fragment>
  );
}

"use client";
import * as React from "react";
import { styled } from "@mui/material/styles";
import Button from "@mui/material/Button";
import CloudUploadIcon from "@mui/icons-material/CloudUpload";
import { Box, Typography } from "@mui/material";

const VisuallyHiddenInput = styled("input")({
  clip: "rect(0 0 0 0)",
  clipPath: "inset(50%)",
  height: 1,
  overflow: "hidden",
  position: "absolute",
  bottom: 0,
  left: 0,
  whiteSpace: "nowrap",
  width: 1,
});

export interface ScanResult {
  fileType: string;
  result: "Clean" | "Suspicious";
  findings: string[];
  executionTimeMs: number;
  executionTimeSec: number;
  stepTimings?: Array<{ label: string; timeMs: number }>;
}

interface InputFileUploadProps {
  validator: {
    scan_from_bytes: (
      data: Uint8Array,
      fileName: string
    ) => {
      fileType?: string;
      result: string;
      findings?: string[];
      executionTimeMs?: number | string;
      executionTimeSec?: number | string;
      stepTimings?: Array<{ label: string; timeMs: number }>;
    };
  } | null;
  onScanComplete?: (result: ScanResult | null) => void;
}

export default function InputFileUpload({
  validator,
  onScanComplete,
}: InputFileUploadProps) {
  const [isLoading, setIsLoading] = React.useState(false);
  const [selectedFile, setSelectedFile] = React.useState<File | null>(null);

  const handleFileChange = async (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    if (!event.target.files || event.target.files.length === 0) {
      return;
    }

    const file = event.target.files[0];
    setSelectedFile(file);

    if (validator) {
      setIsLoading(true);
      try {
        // Read file as ArrayBuffer
        const arrayBuffer = await file.arrayBuffer();
        // Convert to Uint8Array for WASM
        const uint8Array = new Uint8Array(arrayBuffer);

        // Call the WASM function
        const result = validator.scan_from_bytes(uint8Array, file.name);
        // console.log("Raw result from WASM:", result);

        // Ensure executionTimeMs and executionTimeSec are properly converted to numbers
        const executionTimeMs =
          typeof result.executionTimeMs === "number"
            ? result.executionTimeMs
            : result.executionTimeMs !== undefined
            ? parseFloat(result.executionTimeMs)
            : 0;
        const executionTimeSec =
          typeof result.executionTimeSec === "number"
            ? result.executionTimeSec
            : result.executionTimeSec !== undefined
            ? parseFloat(result.executionTimeSec)
            : 0;

        const scanResult: ScanResult = {
          fileType: result.fileType || "Unknown",
          result: (result.result === "Clean" ? "Clean" : "Suspicious") as
            | "Clean"
            | "Suspicious",
          findings: Array.isArray(result.findings) ? result.findings : [],
          executionTimeMs,
          executionTimeSec,
          stepTimings: Array.isArray(result.stepTimings)
            ? result.stepTimings
            : undefined,
        };

        // console.log("Processed scan result:", scanResult);

        // Call the callback with the result
        if (onScanComplete) {
          onScanComplete(scanResult);
        }
      } catch (error) {
        console.error("Error scanning file:", error);
        if (onScanComplete) {
          onScanComplete(null);
        }
      } finally {
        setIsLoading(false);
      }
    }
  };

  return (
    <Box
      sx={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        gap: 2,
      }}
    >
      <Button
        component="label"
        role={undefined}
        variant="outlined"
        tabIndex={-1}
        loading={isLoading || !validator}
        loadingPosition="start"
        startIcon={<CloudUploadIcon />}
        // startIcon={isLoading ? <CircularProgress size={24} color="inherit" /> : <CloudUploadIcon />}
        // disabled={isLoading || !validator}
      >
        {isLoading ? "Scanning..." : "Upload file"}
        <VisuallyHiddenInput
          type="file"
          onChange={handleFileChange}
          accept=".pdf,.docx,.jpg,.jpeg,.png"
          disabled={isLoading || !validator}
        />
      </Button>
      {selectedFile && (
        <Typography variant="body2" color="text.secondary">
          Selected: {selectedFile.name}
        </Typography>
      )}
      {!validator && (
        <Typography variant="body2" color="error">
          WASM module is loading, please wait...
        </Typography>
      )}
    </Box>
  );
}

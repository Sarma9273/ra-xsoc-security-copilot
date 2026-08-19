import type {
  AnalyzeRequest,
  AnalyzeResponse,
  ApiErrorResponse,
} from "../types/api";

const configuredApiBaseUrl = import.meta.env.VITE_API_BASE_URL?.trim();

const API_BASE_URL = configuredApiBaseUrl
  ? configuredApiBaseUrl.replace(/\/$/, "")
  : "";
  
export class ApiRequestError extends Error {
  requestId?: string;
  status: number;

  constructor(message: string, status: number, requestId?: string) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
    this.requestId = requestId;
  }
}

export async function analyzeIncident(
  request: AnalyzeRequest,
): Promise<AnalyzeResponse> {
  if (!API_BASE_URL) {
    throw new ApiRequestError(
      "RA-XSOC API is not configured for this deployment.",
      503,
    );
  }

  const response = await fetch(`${API_BASE_URL}/api/v1/analyze`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });

  if (!response.ok) {
    let errorPayload: ApiErrorResponse | null = null;

    try {
      errorPayload = (await response.json()) as ApiErrorResponse;
    } catch {
      // Response was not JSON.
    }

    throw new ApiRequestError(
      errorPayload?.error?.message ?? "Unable to analyze incident.",
      response.status,
      errorPayload?.request_id,
    );
  }

  return (await response.json()) as AnalyzeResponse;
}

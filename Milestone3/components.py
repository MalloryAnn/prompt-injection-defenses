from dash import html, dcc
from styles import CARD_STYLE, COLORS, GRADIENT_TEXT

ML_THRESHOLD = 0.50

def gradient_title(text: str, size: str = "24px") -> html.Div:
    return html.Div(
        text,
        style={
            **GRADIENT_TEXT,
            "fontSize": size,
            "fontWeight": "950",
            "margin": "0 0 14px 0",
            "letterSpacing": "-0.02em",
        },
    )

def mixed_gradient_title(parts, size="32px") -> html.Div:
    """
    parts = list of tuples:
    [("Prompt ", False), ("Injection", True), (" Guardrail", False)]
    """
    children = []

    for text, is_gradient in parts:
        if is_gradient:
            children.append(html.Span(text, style=GRADIENT_TEXT))
        else:
            children.append(html.Span(text, style={"color": "#1f2937"}))

    return html.Div(
        children,
        style={
            "fontSize": size,
            "fontWeight": "950",
            "margin": "0 0 14px 0",
            "letterSpacing": "-0.035em",
            "lineHeight": "1.05",
        },
    )

def feature_chip(text: str) -> html.Div:
    return html.Div(
        text,
        style={
            "padding": "14px 22px",
            "borderRadius": "999px",
            "background": "rgba(255,255,255,0.58)",
            "backdropFilter": "blur(14px)",
            "WebkitBackdropFilter": "blur(14px)",
            "border": "1px solid rgba(255,255,255,0.65)",
            "boxShadow": "0 6px 16px rgba(0,0,0,0.06), 0 12px 32px rgba(0,0,0,0.10)",
            "fontSize": "16px",
            "color": "#1e293b",
            "fontWeight": "700",
            "letterSpacing": "-0.01em",
            "whiteSpace": "nowrap",
            "flexShrink": "1",
        },
    )
def contribution_card() -> html.Div:
    return html.Div(
        [
            html.Div(
                "PROTECT AI DASHBOARD",
                style={
                    "fontSize": "12px",
                    "fontWeight": "800",
                    "letterSpacing": "0.12em",
                    "textTransform": "uppercase",
                    "color": "#0b0b0b",
                    "marginBottom": "12px",
                },
            ),

            html.H1(
                "Prompt Injection Guardrail",
                style={
                    **GRADIENT_TEXT,
                    "margin": "0 0 14px 0",
                    "fontSize": "64px",
                    "lineHeight": "1.02",
                    "letterSpacing": "-0.055em",
                    "fontWeight": "850",
                },
            ),

            html.P(
                "A multi-layer protection system that analyzes prompts, scores risk, and explains each decision before output is trusted.",
                style={
                    "color": "#475569",
                    "fontSize": "18px",
                    "lineHeight": "1.55",
                    "maxWidth": "1000px",
                    "margin": "0 0 26px 0",
                    "fontWeight": "400",
                },
            ),

            html.Div(
                [
                    feature_chip("Heuristic Detection"),
                    feature_chip("ML Classification"),
                    feature_chip("Risk Scoring"),
                    feature_chip("Explainable Decisions"),
                ],
                style={
                    "display": "flex",
                    "justifyContent": "space-between",
                    "gap": "16px",
                    "flexWrap": "nowrap",
                    "alignItems": "center",
                    "width": "100%",
                },
            ),
        ],
        style={
            **CARD_STYLE,
            "padding": "42px 46px",
            "height": "100%",
            "border": "1px solid rgba(255,255,255,0.65)",
            "background": (
                "linear-gradient(135deg, rgba(255,255,255,0.92), "
                "rgba(255,255,255,0.62))"
            ),
            "boxShadow": "0 22px 70px rgba(15,23,42,0.10)",
            "position": "relative",
            "overflow": "hidden",
        },
    )
def prompt_test_card(prompt_options, default_prompt) -> html.Div:
    button_style = {
        "padding": "8px 12px", "borderRadius": "10px", "border": "1px solid #cbd5e1",
        "fontSize": "12px", "fontWeight": "700", "cursor": "pointer",
    }
    return html.Div(
        [
            mixed_gradient_title([
                ("Live", True),  # gradient
                (" Prompt Test", False),  # black
            ], "28px"),
            html.P("Choose a prompt from the 1000-prompt dataset or type your own prompt to trace the guardrail decision path.", style={"color": "#405064", "marginTop": 0, "fontSize": "13px"}),
            dcc.Dropdown(
                id="prompt-picker",
                options=prompt_options,
                placeholder="Search prompts from prompts.txt...",
                searchable=True,
                clearable=True,
                optionHeight=52,
                maxHeight=300,
                className="custom-dropdown",
                # ADD position: relative HERE
                style={"fontSize": "13px", "marginBottom": "14px", "position": "relative"},

            ),
            html.Div(
                [
                    html.Button("Benign", id="sample-benign", n_clicks=0, style={**button_style, "background": COLORS["safe_bg"], "color": COLORS["safe_text"]}),
                    html.Button("Borderline", id="sample-borderline", n_clicks=0, style={**button_style, "background": COLORS["border_bg"], "color": COLORS["border_text"]}),
                    html.Button("ML Catch", id="sample-ml", n_clicks=0, style={**button_style, "background": "#ffe6e4", "color": COLORS["flag_text"]}),
                    html.Button("Heuristic Catch", id="sample-heuristic", n_clicks=0, style={**button_style, "background": "#ffe6e4", "color": COLORS["flag_text"]}),
                    html.Button("Strong Attack", id="sample-strong", n_clicks=0, style={**button_style, "background": "#ffe6e4", "color": COLORS["flag_text"]}),
                ],
                style={"display": "flex", "gap": "10px", "flexWrap": "wrap", "marginTop": "14px", "marginBottom": "14px",},
            ),
            dcc.Textarea(
                id="prompt-input",
                value=default_prompt,
                style={"width": "100%", "maxWidth": "100%", "height": "130px", "padding": "12px", "borderRadius": "14px", "border": "1px solid #cfd9e5", "resize": "vertical", "fontSize": "14px"},
            ),
            html.Button("Analyze Prompt", id="analyze-button", n_clicks=0, style={"marginTop": "10px", "padding": "10px 16px", "borderRadius": "12px", "border": "none", "cursor": "pointer", "background": "#111827", "color": "white", "fontWeight": "800"}),
        ],
        style={
            **CARD_STYLE,
            "padding": "18px",
            "height": "100%",
            "overflow": "visible",
            "position": "relative",
            "zIndex": 50,
        },
    )
def status_pill(title: str, state: str, detail: str = "", score=None) -> html.Div:
    if state == "flagged":
        label, bg, border, color, icon = "FLAGGED", COLORS["flag_bg"], COLORS["flag_border"], COLORS["flag_text"], "!"
    elif state == "borderline":
        label, bg, border, color, icon = "BORDERLINE", COLORS["border_bg"], COLORS["border_border"], COLORS["border_text"], "!"
    else:
        label, bg, border, color, icon = "SAFE", COLORS["safe_bg"], COLORS["safe_border"], COLORS["safe_text"], "✓"

    score_line = []
    if score is not None and score != "N/A":
        score_line = [html.Div(f"Risk Score: {float(score):.2f} | Threshold: {ML_THRESHOLD:.2f}", style={"fontSize": "11px", "color": COLORS["muted"], "marginTop": "4px"})]

    return html.Div(
        [
            html.Div([html.Div(title, style={"fontSize": "12px", "fontWeight": "800", "color": COLORS["muted"]}), html.Div(icon, style={"fontSize": "20px", "fontWeight": "900", "color": color})], style={"display": "flex", "alignItems": "center", "justifyContent": "space-between"}),
            html.Div(label, style={"fontSize": "17px", "fontWeight": "900", "marginTop": "4px", "color": color}),
            html.Div(detail, style={"fontSize": "11px", "color": COLORS["muted"], "marginTop": "3px"}),
            *score_line,
        ],
        style={"background": bg, "border": f"1px solid {border}", "borderRadius": "14px", "padding": "12px", "flex": "1 1 170px", "minWidth": "0"},
    )
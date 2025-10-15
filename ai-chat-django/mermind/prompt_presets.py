# mermind/prompt_presets.py
DIAGRAM_TYPES = [
    "flowchart","sequence","state","er","class","journey","gantt",
    "timeline","pie","mindmap","gitGraph","quadrant"
]

CLASSIFIER_SYSTEM = """You classify a user's request to the best Mermaid diagram type.
Return strict JSON: {"type":"<one of: flowchart,sequence,state,er,class,journey,gantt,timeline,pie,mindmap,gitGraph,quadrant>","reason":"..."}"""

GEN_TEMPLATES = {
    "flowchart": "flowchart TD\n%% keep it concise\n",
    "sequence": "sequenceDiagram\n",
    "state": "stateDiagram-v2\n[*] --> State1\n",
    "er": "erDiagram\n",
    "class": "classDiagram\n",
    "journey": "journey\n\ntitle User Journey\n",
    "gantt": "gantt\n    dateFormat  YYYY-MM-DD\n    title Roadmap\n",
    "timeline": "timeline\n    title Timeline\n",
    "pie": "pie title Breakdown\n",
    "mindmap": "mindmap\n  root) Topic\n",
    "gitGraph": "gitGraph\n  commit\n",
    "quadrant": "quadrantChart\n  title Matrix\n  x-axis Low --> High\n  y-axis Low --> High\n",
}

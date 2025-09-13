# shadowscan/trackers/graph_exporter.py
"""Graph exporter for JSON and HTML visualization formats."""

import json
from pathlib import Path
from typing import Dict, Any, Optional
import logging
from datetime import datetime

from shadowscan.utils.schema import InteractionGraph, GraphNode, GraphEdge

logger = logging.getLogger(__name__)

class GraphExporter:
    """Export interaction graphs to various formats for visualization."""
    
    def __init__(self):
        self.d3_template = self._get_d3_template()
        self.cytoscape_template = self._get_cytoscape_template()
    
    def export_graph(self, graph: InteractionGraph, out_path: str, 
                    html: bool = False, format_type: str = 'd3') -> str:
        """
        Export graph to JSON and optionally HTML visualization.
        
        Args:
            graph: InteractionGraph to export
            out_path: Output file path (without extension)
            html: Whether to generate HTML visualization
            format_type: HTML format ('d3' or 'cytoscape')
            
        Returns:
            Path to the main exported file
        """
        try:
            base_path = Path(out_path)
            base_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Export JSON
            json_path = base_path.with_suffix('.json')
            json_data = self._convert_to_json_format(graph)
            
            with open(json_path, 'w') as f:
                json.dump(json_data, f, indent=2, default=str)
            
            logger.info(f"Graph JSON exported to: {json_path}")
            
            # Export HTML if requested
            if html:
                html_path = base_path.with_suffix('.html')
                self._export_html_visualization(json_data, html_path, format_type)
                logger.info(f"Graph HTML exported to: {html_path}")
                return str(html_path)
            
            return str(json_path)
            
        except Exception as e:
            logger.error(f"Error exporting graph: {e}")
            return ""
    
    def _convert_to_json_format(self, graph: InteractionGraph) -> Dict[str, Any]:
        """Convert InteractionGraph to JSON-serializable format."""
        return {
            'metadata': graph.metadata,
            'nodes': [self._node_to_dict(node) for node in graph.nodes],
            'edges': [self._edge_to_dict(edge) for edge in graph.edges],
            'export_timestamp': datetime.now().isoformat(),
            'format_version': '1.0'
        }
    
    def _node_to_dict(self, node: GraphNode) -> Dict[str, Any]:
        """Convert GraphNode to dictionary."""
        # Get visualization properties based on node type
        node_config = self._get_node_visualization_config(node.type)
        
        return {
            'id': node.id,
            'label': node.label,
            'type': node.type,
            'metadata': node.metadata,
            'visualization': {
                'color': node_config['color'],
                'size': node_config['size'],
                'priority': node_config['priority']
            }
        }
    
    def _edge_to_dict(self, edge: GraphEdge) -> Dict[str, Any]:
        """Convert GraphEdge to dictionary."""
        # Get visualization properties based on edge type
        edge_config = self._get_edge_visualization_config(edge.type)
        
        return {
            'source': edge.source,
            'target': edge.target,
            'type': edge.type,
            'weight': edge.weight,
            'metadata': edge.metadata,
            'visualization': {
                'color': edge_config['color'],
                'width': max(1, min(10, edge.weight)),  # Scale width by weight
                'style': edge_config['style']
            }
        }
    
    def _get_node_visualization_config(self, node_type: str) -> Dict[str, Any]:
        """Get visualization configuration for node type."""
        configs = {
            'target': {'color': '#ff4444', 'size': 50, 'priority': 10},
            'dex': {'color': '#44ff44', 'size': 40, 'priority': 8},
            'token': {'color': '#4444ff', 'size': 30, 'priority': 6},
            'oracle': {'color': '#ffaa44', 'size': 35, 'priority': 7},
            'proxy': {'color': '#aa44ff', 'size': 25, 'priority': 5},
            'contract': {'color': '#888888', 'size': 20, 'priority': 3},
            'eoa': {'color': '#cccccc', 'size': 15, 'priority': 1}
        }
        return configs.get(node_type, configs['contract'])
    
    def _get_edge_visualization_config(self, edge_type: str) -> Dict[str, Any]:
        """Get visualization configuration for edge type."""
        configs = {
            'call': {'color': '#666666', 'width': 2, 'style': 'solid'},
            'transfer': {'color': '#00aa00', 'width': 3, 'style': 'solid'},
            'approval': {'color': '#aa0000', 'width': 2, 'style': 'dashed'},
            'dex_interaction': {'color': '#0088ff', 'width': 4, 'style': 'solid'},
            'oracle_read': {'color': '#ff8800', 'width': 2, 'style': 'dotted'},
            'proxy_call': {'color': '#8800ff', 'width': 3, 'style': 'solid'},
            'admin': {'color': '#ff0000', 'width': 2, 'style': 'dashed'}
        }
        return configs.get(edge_type, configs['call'])
    
    def _export_html_visualization(self, json_data: Dict[str, Any], 
                                  html_path: Path, format_type: str):
        """Export HTML visualization."""
        if format_type == 'd3':
            html_content = self._generate_d3_html(json_data)
        elif format_type == 'cytoscape':
            html_content = self._generate_cytoscape_html(json_data)
        else:
            raise ValueError(f"Unsupported format type: {format_type}")
        
        with open(html_path, 'w') as f:
            f.write(html_content)
    
    def _generate_d3_html(self, json_data: Dict[str, Any]) -> str:
        """Generate D3.js HTML visualization."""
        return self.d3_template.format(
            graph_data=json.dumps(json_data, indent=2, default=str),
            title=f"Contract Interaction Graph - {json_data.get('metadata', {}).get('target_address', 'Unknown')}",
            node_count=len(json_data.get('nodes', [])),
            edge_count=len(json_data.get('edges', []))
        )
    
    def _generate_cytoscape_html(self, json_data: Dict[str, Any]) -> str:
        """Generate Cytoscape.js HTML visualization."""
        # Convert format for Cytoscape.js
        cytoscape_data = self._convert_to_cytoscape_format(json_data)
        
        return self.cytoscape_template.format(
            graph_data=json.dumps(cytoscape_data, indent=2, default=str),
            title=f"Contract Interaction Graph - {json_data.get('metadata', {}).get('target_address', 'Unknown')}",
            node_count=len(json_data.get('nodes', [])),
            edge_count=len(json_data.get('edges', []))
        )
    
    def _convert_to_cytoscape_format(self, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert to Cytoscape.js format."""
        elements = []
        
        # Add nodes
        for node in json_data.get('nodes', []):
            elements.append({
                'data': {
                    'id': node['id'],
                    'label': node['label'],
                    'type': node['type'],
                    'color': node['visualization']['color'],
                    'size': node['visualization']['size']
                }
            })
        
        # Add edges
        for edge in json_data.get('edges', []):
            elements.append({
                'data': {
                    'id': f"{edge['source']}-{edge['target']}",
                    'source': edge['source'],
                    'target': edge['target'],
                    'type': edge['type'],
                    'weight': edge['weight'],
                    'color': edge['visualization']['color'],
                    'width': edge['visualization']['width']
                }
            })
        
        return {'elements': elements}
    
    def _get_d3_template(self) -> str:
        """D3.js HTML template for graph visualization."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: #2c3e50;
            color: white;
            padding: 20px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
        }}
        .stats {{
            margin-top: 10px;
            opacity: 0.9;
        }}
        .graph-container {{
            position: relative;
            height: 80vh;
            overflow: hidden;
        }}
        .controls {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(255,255,255,0.9);
            padding: 10px;
            border-radius: 5px;
            z-index: 1000;
        }}
        .node {{
            stroke: #fff;
            stroke-width: 1.5px;
            cursor: pointer;
        }}
        .link {{
            stroke-opacity: 0.6;
        }}
        .node-label {{
            font: 10px sans-serif;
            text-anchor: middle;
            pointer-events: none;
        }}
        .tooltip {{
            position: absolute;
            background: rgba(0,0,0,0.8);
            color: white;
            padding: 8px;
            border-radius: 4px;
            font-size: 12px;
            pointer-events: none;
            z-index: 1001;
        }}
        .legend {{
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: rgba(255,255,255,0.9);
            padding: 15px;
            border-radius: 5px;
            font-size: 12px;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }}
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <div class="stats">
                Nodes: {node_count} | Edges: {edge_count}
            </div>
        </div>
        <div class="graph-container">
            <div class="controls">
                <button onclick="resetZoom()">Reset View</button>
                <button onclick="toggleLabels()">Toggle Labels</button>
            </div>
            <svg id="graph"></svg>
            <div class="tooltip" id="tooltip" style="display: none;"></div>
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #44ff44;"></div>
                    <span>DEX</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #4444ff;"></div>
                    <span>Token</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ffaa44;"></div>
                    <span>Oracle</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #888888;"></div>
                    <span>Contract</span>
                </div>
            </div>
        </div>
    </div>

    <script>
        const graphData = {graph_data};
        
        const width = document.getElementById('graph').clientWidth || 800;
        const height = document.getElementById('graph').clientHeight || 600;
        
        const svg = d3.select("#graph")
            .attr("width", width)
            .attr("height", height);
            
        const g = svg.append("g");
        
        // Add zoom behavior
        const zoom = d3.zoom()
            .scaleExtent([0.1, 10])
            .on("zoom", (event) => {{
                g.attr("transform", event.transform);
            }});
            
        svg.call(zoom);
        
        // Create simulation
        const simulation = d3.forceSimulation(graphData.nodes)
            .force("link", d3.forceLink(graphData.edges).id(d => d.id).distance(d => 100 / Math.sqrt(d.weight || 1)))
            .force("charge", d3.forceManyBody().strength(d => -300 * (d.visualization.size / 20)))
            .force("center", d3.forceCenter(width / 2, height / 2))
            .force("collision", d3.forceCollide().radius(d => d.visualization.size / 2 + 5));
        
        // Create links
        const link = g.append("g")
            .attr("class", "links")
            .selectAll("line")
            .data(graphData.edges)
            .enter().append("line")
            .attr("class", "link")
            .style("stroke", d => d.visualization.color)
            .style("stroke-width", d => d.visualization.width)
            .style("stroke-dasharray", d => d.visualization.style === 'dashed' ? '5,5' : 
                                         d.visualization.style === 'dotted' ? '2,2' : 'none');
        
        // Create nodes
        const node = g.append("g")
            .attr("class", "nodes")
            .selectAll("circle")
            .data(graphData.nodes)
            .enter().append("circle")
            .attr("class", "node")
            .attr("r", d => d.visualization.size / 2)
            .style("fill", d => d.visualization.color)
            .call(d3.drag()
                .on("start", dragstarted)
                .on("drag", dragged)
                .on("end", dragended));
        
        // Add labels
        let labels = g.append("g")
            .attr("class", "labels")
            .selectAll("text")
            .data(graphData.nodes)
            .enter().append("text")
            .attr("class", "node-label")
            .style("font-size", "10px")
            .style("fill", "#333")
            .text(d => d.label.split('\\n')[0]); // Show only first line
        
        // Tooltip
        const tooltip = d3.select("#tooltip");
        
        node.on("mouseover", function(event, d) {{
            tooltip
                .style("display", "block")
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px")
                .html(`
                    <strong>${{d.label}}</strong><br/>
                    Type: ${{d.type}}<br/>
                    Address: ${{d.id}}<br/>
                    Connections: ${{d.metadata.edge_count || 0}}<br/>
                    Importance: ${{(d.metadata.importance_score || 0).toFixed(2)}}
                `);
        }})
        .on("mouseout", function() {{
            tooltip.style("display", "none");
        }});
        
        link.on("mouseover", function(event, d) {{
            tooltip
                .style("display", "block")
                .style("left", (event.pageX + 10) + "px")
                .style("top", (event.pageY - 10) + "px")
                .html(`
                    <strong>${{d.type.replace('_', ' ').toUpperCase()}}</strong><br/>
                    From: ${{d.source}}<br/>
                    To: ${{d.target}}<br/>
                    Weight: ${{d.weight.toFixed(2)}}
                `);
        }})
        .on("mouseout", function() {{
            tooltip.style("display", "none");
        }});
        
        // Update positions
        simulation.on("tick", () => {{
            link
                .attr("x1", d => d.source.x)
                .attr("y1", d => d.source.y)
                .attr("x2", d => d.target.x)
                .attr("y2", d => d.target.y);
                
            node
                .attr("cx", d => d.x)
                .attr("cy", d => d.y);
                
            labels
                .attr("x", d => d.x)
                .attr("y", d => d.y - d.visualization.size / 2 - 5);
        }});
        
        // Drag functions
        function dragstarted(event, d) {{
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
        }}
        
        function dragged(event, d) {{
            d.fx = event.x;
            d.fy = event.y;
        }}
        
        function dragended(event, d) {{
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
        }}
        
        // Control functions
        function resetZoom() {{
            svg.transition().duration(750).call(
                zoom.transform,
                d3.zoomIdentity
            );
        }}
        
        let labelsVisible = true;
        function toggleLabels() {{
            labelsVisible = !labelsVisible;
            labels.style("display", labelsVisible ? "block" : "none");
        }}
    </script>
</body>
</html>'''

    def _get_cytoscape_template(self) -> str:
        """Cytoscape.js HTML template for graph visualization."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <script src="https://unpkg.com/cytoscape@3.23.0/dist/cytoscape.min.js"></script>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
        }}
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        .header {{
            background: #2c3e50;
            color: white;
            padding: 20px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 24px;
        }}
        .stats {{
            margin-top: 10px;
            opacity: 0.9;
        }}
        #cy {{
            width: 100%;
            height: 80vh;
            background: #fafafa;
        }}
        .controls {{
            position: absolute;
            top: 10px;
            right: 10px;
            background: rgba(255,255,255,0.9);
            padding: 10px;
            border-radius: 5px;
            z-index: 1000;
        }}
        .legend {{
            position: absolute;
            bottom: 10px;
            left: 10px;
            background: rgba(255,255,255,0.9);
            padding: 15px;
            border-radius: 5px;
            font-size: 12px;
            z-index: 1000;
        }}
        .legend-item {{
            display: flex;
            align-items: center;
            margin-bottom: 5px;
        }}
        .legend-color {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
            margin-right: 8px;
        }}
        button {{
            background: #3498db;
            color: white;
            border: none;
            padding: 8px 12px;
            border-radius: 4px;
            cursor: pointer;
            margin-right: 5px;
        }}
        button:hover {{
            background: #2980b9;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{title}</h1>
            <div class="stats">
                Nodes: {node_count} | Edges: {edge_count}
            </div>
        </div>
        <div style="position: relative;">
            <div class="controls">
                <button onclick="cy.fit()">Fit View</button>
                <button onclick="cy.center()">Center</button>
                <button onclick="runLayout('cose')">Cose Layout</button>
                <button onclick="runLayout('circle')">Circle Layout</button>
            </div>
            <div id="cy"></div>
            <div class="legend">
                <div class="legend-item">
                    <div class="legend-color" style="background: #ff4444;"></div>
                    <span>Target Contract</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #44ff44;"></div>
                    <span>DEX</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #4444ff;"></div>
                    <span>Token</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #ffaa44;"></div>
                    <span>Oracle</span>
                </div>
                <div class="legend-item">
                    <div class="legend-color" style="background: #888888;"></div>
                    <span>Contract</span>
                </div>
            </div>
        </div>
    </div>

    <script>
        const graphData = {graph_data};
        
        const cy = cytoscape({{
            container: document.getElementById('cy'),
            elements: graphData.elements,
            
            style: [
                {{
                    selector: 'node',
                    style: {{
                        'background-color': 'data(color)',
                        'width': 'data(size)',
                        'height': 'data(size)',
                        'label': 'data(label)',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'font-size': '10px',
                        'color': '#333',
                        'text-outline-color': '#fff',
                        'text-outline-width': '2px'
                    }}
                }},
                {{
                    selector: 'edge',
                    style: {{
                        'width': 'data(width)',
                        'line-color': 'data(color)',
                        'target-arrow-color': 'data(color)',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'opacity': 0.7
                    }}
                }},
                {{
                    selector: 'node:selected',
                    style: {{
                        'border-width': '3px',
                        'border-color': '#000'
                    }}
                }},
                {{
                    selector: 'edge:selected',
                    style: {{
                        'width': 'mapData(width, 1, 10, 3, 12)',
                        'opacity': 1
                    }}
                }}
            ],
            
            layout: {{
                name: 'cose',
                idealEdgeLength: 100,
                nodeOverlap: 20,
                refresh: 20,
                fit: true,
                padding: 30,
                randomize: false,
                componentSpacing: 100,
                nodeRepulsion: 400000,
                edgeElasticity: 100,
                nestingFactor: 5,
                gravity: 80,
                numIter: 1000,
                initialTemp: 200,
                coolingFactor: 0.95,
                minTemp: 1.0
            }}
        }});
        
        // Add tooltips
        cy.nodes().qtip({{
            content: function() {{
                const node = this;
                return `
                    <strong>${{node.data('label')}}</strong><br/>
                    Type: ${{node.data('type')}}<br/>
                    ID: ${{node.id()}}<br/>
                    Degree: ${{node.degree()}}
                `;
            }},
            position: {{
                my: 'bottom center',
                at: 'top center'
            }},
            style: {{
                classes: 'qtip-bootstrap',
                tip: {{
                    width: 16,
                    height: 8
                }}
            }}
        }});
        
        cy.edges().qtip({{
            content: function() {{
                const edge = this;
                return `
                    <strong>${{edge.data('type').replace('_', ' ').toUpperCase()}}</strong><br/>
                    Weight: ${{edge.data('weight').toFixed(2)}}<br/>
                    From: ${{edge.source().id()}}<br/>
                    To: ${{edge.target().id()}}
                `;
            }},
            position: {{
                my: 'bottom center',
                at: 'center center'
            }},
            style: {{
                classes: 'qtip-bootstrap'
            }}
        }});
        
        // Layout functions
        function runLayout(layoutName) {{
            const layouts = {{
                'cose': {{
                    name: 'cose',
                    idealEdgeLength: 100,
                    nodeOverlap: 20,
                    refresh: 20,
                    fit: true,
                    padding: 30,
                    randomize: false,
                    componentSpacing: 100,
                    nodeRepulsion: 400000,
                    edgeElasticity: 100,
                    nestingFactor: 5,
                    gravity: 80,
                    numIter: 1000,
                    initialTemp: 200,
                    coolingFactor: 0.95,
                    minTemp: 1.0
                }},
                'circle': {{
                    name: 'circle',
                    fit: true,
                    padding: 30,
                    boundingBox: undefined,
                    avoidOverlap: true,
                    nodeDimensionsIncludeLabels: false,
                    spacingFactor: undefined,
                    radius: undefined,
                    startAngle: 3 / 2 * Math.PI,
                    sweep: undefined,
                    clockwise: true,
                    sort: undefined,
                    animate: false,
                    animationDuration: 500,
                    animationEasing: undefined,
                    ready: undefined,
                    stop: undefined
                }}
            }};
            
            const layout = cy.layout(layouts[layoutName]);
            layout.run();
        }}
        
        // Highlight connected nodes on selection
        cy.on('select', 'node', function(evt) {{
            const node = evt.target;
            const neighborhood = node.neighborhood();
            
            cy.elements().addClass('faded');
            node.removeClass('faded');
            neighborhood.removeClass('faded');
        }});
        
        cy.on('unselect', 'node', function(evt) {{
            cy.elements().removeClass('faded');
        }});
        
        // Add faded style
        cy.style()
            .selector('.faded')
            .style({{
                'opacity': 0.25,
                'text-opacity': 0
            }})
            .update();
    </script>
    
    <!-- QTip2 for tooltips -->
    <script src="https://cdn.jsdelivr.net/npm/qtip2@3.0.3/dist/jquery.qtip.min.js"></script>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/qtip2@3.0.3/dist/jquery.qtip.min.css">
</body>
</html>'''

    def export_summary_report(self, graph: InteractionGraph, json_data: Dict[str, Any], 
                             out_path: str) -> str:
        """Export a human-readable summary report."""
        try:
            report_path = Path(out_path).with_suffix('.md')
            
            # Generate markdown report
            report_content = self._generate_markdown_report(graph, json_data)
            
            with open(report_path, 'w') as f:
                f.write(report_content)
            
            logger.info(f"Summary report exported to: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Error exporting summary report: {e}")
            return ""
    
    def _generate_markdown_report(self, graph: InteractionGraph, json_data: Dict[str, Any]) -> str:
        """Generate markdown summary report."""
        metadata = graph.metadata
        target_address = metadata.get('target_address', 'Unknown')
        
        report = f"""# Contract Interaction Graph Report

**Target Contract:** `{target_address}`  
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Session ID:** {metadata.get('session_id', 'Unknown')}

## Graph Overview

- **Nodes:** {metadata.get('node_count', 0)}
- **Edges:** {metadata.get('edge_count', 0)}
- **Graph Density:** {metadata.get('graph_density', 0):.3f}
- **Total Edge Weight:** {metadata.get('total_edge_weight', 0):.2f}

## Node Distribution

"""
        
        # Node types breakdown
        node_types = metadata.get('node_types', {})
        for node_type, count in sorted(node_types.items(), key=lambda x: x[1], reverse=True):
            report += f"- **{node_type.title()}:** {count}\n"
        
        report += "\n## Edge Distribution\n\n"
        
        # Edge types breakdown
        edge_types = metadata.get('edge_types', {})
        for edge_type, count in sorted(edge_types.items(), key=lambda x: x[1], reverse=True):
            formatted_type = edge_type.replace('_', ' ').title()
            report += f"- **{formatted_type}:** {count}\n"
        
        # Most connected nodes
        most_connected = metadata.get('most_connected_nodes', [])
        if most_connected:
            report += "\n## Most Connected Nodes\n\n"
            for i, node in enumerate(most_connected[:5], 1):
                report += f"{i}. **{node['type'].title()}** `{node['address']}` ({node['degree']} connections)\n"
        
        # Strongest edges
        strongest_edges = metadata.get('strongest_edges', [])
        if strongest_edges:
            report += "\n## Strongest Relationships\n\n"
            for i, edge in enumerate(strongest_edges[:5], 1):
                edge_type = edge['type'].replace('_', ' ').title()
                report += f"{i}. **{edge_type}** `{edge['source']}` → `{edge['target']}` (weight: {edge['weight']:.2f})\n"
        
        report += f"\n## Analysis Notes\n\n"
        report += f"This graph represents the interaction patterns for contract `{target_address}`. "
        report += f"The visualization shows {metadata.get('node_count', 0)} related addresses with "
        report += f"{metadata.get('edge_count', 0)} documented relationships.\n\n"
        
        if metadata.get('graph_density', 0) > 0.5:
            report += "⚠️ **High Density Graph:** This contract has many interconnected relationships, "
            report += "indicating complex interaction patterns that may require detailed analysis.\n\n"
        
        return report

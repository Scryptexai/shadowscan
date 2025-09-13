import click
from shadowscan.integrations.ai.zhipu_agent import ZhipuAgent

@click.command()
@click.option("--task", "-t", required=True, help="Instruction for AI agent")
def ai(task):
    """Use AI agent (GLM-4.5) for coding & analysis"""
    try:
        agent = ZhipuAgent()
        result = agent.chat(task)
        click.echo(result)
    except Exception as e:
        click.echo(f"Error: {e}")

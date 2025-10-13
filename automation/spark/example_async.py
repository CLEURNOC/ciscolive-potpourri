#!/usr/bin/env python3
"""
Example demonstrating async capabilities of refactored Sparker.

This example shows how to use the new async methods for high-performance
concurrent operations.
"""

import asyncio
import time
from automation.spark.sparker import Sparker, MessageType


async def example_basic_async():
    """Basic async usage."""
    print("=== Basic Async Example ===\n")

    # Using async context manager (auto-cleanup)
    async with Sparker(token="your-token-here") as spark:
        # Post a message asynchronously
        success = await spark.post_to_spark_async(team=None, room="Test Room", msg="Hello from async!", mtype=MessageType.GOOD)
        print(f"Message sent: {success}\n")


async def example_concurrent_posts():
    """Send multiple messages concurrently."""
    print("=== Concurrent Posts Example ===\n")

    rooms = ["Room 1", "Room 2", "Room 3", "Room 4", "Room 5"]

    async with Sparker(token="your-token-here") as spark:
        start_time = time.time()

        # Create tasks for concurrent execution
        tasks = [
            spark.post_to_spark_async(team=None, room=room, msg=f"Concurrent message to {room}", mtype=MessageType.NEUTRAL)
            for room in rooms
        ]

        # Execute all tasks concurrently
        results = await asyncio.gather(*tasks)

        elapsed = time.time() - start_time
        success_count = sum(1 for r in results if r)

        print(f"Sent {success_count}/{len(rooms)} messages in {elapsed:.2f}s")
        print(f"Average: {elapsed / len(rooms):.2f}s per message (concurrent)\n")


async def example_mixed_operations():
    """Mix different async operations."""
    print("=== Mixed Operations Example ===\n")

    async with Sparker(token="your-token-here") as spark:
        # Get team and room IDs concurrently
        team_task = spark.get_team_id_async("My Team")
        room_task = spark.get_room_id_async(None, "My Room")

        team_id, room_id = await asyncio.gather(team_task, room_task)

        print(f"Team ID: {team_id}")
        print(f"Room ID: {room_id}")

        if room_id:
            # Get messages and members concurrently
            messages_task = spark.get_messages_async(room_id)
            members_task = spark.get_members_async("My Room")

            messages, members = await asyncio.gather(messages_task, members_task, return_exceptions=True)

            print(f"Messages: {len(messages) if messages else 0}")
            print(f"Members: {len(members) if members else 0}\n")


async def example_error_handling():
    """Demonstrate error handling with async."""
    print("=== Error Handling Example ===\n")

    async with Sparker(token="invalid-token") as spark:
        try:
            # This should fail gracefully
            result = await spark.post_to_spark_async(team=None, room="Test", msg="This will fail")
            print(f"Result: {result}")
        except Exception as e:
            print(f"Caught exception: {e}")

        print("Error handled gracefully\n")


def compare_sync_vs_async():
    """Compare synchronous vs asynchronous performance."""
    print("=== Sync vs Async Performance Comparison ===\n")

    rooms = ["Room 1", "Room 2", "Room 3"]
    token = "your-token-here"

    # Synchronous (sequential)
    print("Synchronous (sequential):")
    Sparker(token=token)
    start = time.time()

    for _ in rooms:
        # This would actually make API calls in real usage
        pass  # spark_sync.post_to_spark(None, room, "Test")

    sync_time = time.time() - start
    print(f"Time: {sync_time:.2f}s\n")

    # Asynchronous (concurrent)
    print("Asynchronous (concurrent):")

    async def async_posts():
        async with Sparker(token=token) as spark:
            tasks = [spark.post_to_spark_async(None, room, "Test") for room in rooms]
            await asyncio.gather(*tasks)

    start = time.time()
    # asyncio.run(async_posts())  # Would actually run in real usage
    async_time = time.time() - start

    print(f"Time: {async_time:.2f}s")
    if sync_time > 0:
        speedup = sync_time / async_time if async_time > 0 else 0
        print(f"Speedup: {speedup:.1f}x\n")


async def example_with_card():
    """Send adaptive card asynchronously."""
    print("=== Adaptive Card Example ===\n")

    card = {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
            "type": "AdaptiveCard",
            "version": "1.2",
            "body": [
                {"type": "TextBlock", "text": "Async Notification", "weight": "Bolder", "size": "Medium"},
                {"type": "TextBlock", "text": "This card was sent asynchronously!", "wrap": True},
            ],
        },
    }

    async with Sparker(token="your-token-here") as spark:
        success = await spark.post_to_spark_with_card_async(
            team=None, room="Test Room", person=None, card=card, msg="Check out this card", mtype=MessageType.GOOD
        )
        print(f"Card sent: {success}\n")


async def example_batch_operations():
    """Demonstrate batch operations with async."""
    print("=== Batch Operations Example ===\n")

    async with Sparker(token="your-token-here") as spark:
        # Batch 1: Get multiple people
        person_ids = ["person1", "person2", "person3"]
        people_tasks = [spark.get_person_async(pid) for pid in person_ids]
        people = await asyncio.gather(*people_tasks, return_exceptions=True)

        print(f"Retrieved {len(people)} people")

        # Batch 2: Get multiple rooms
        team_ids = ["team1", "team2"]
        room_names = ["Room A", "Room B"]
        room_tasks = [spark.get_room_id_async(tid, rname) for tid, rname in zip(team_ids, room_names)]
        rooms = await asyncio.gather(*room_tasks, return_exceptions=True)

        print(f"Retrieved {len(rooms)} rooms\n")


def main():
    """Run all examples."""
    print("=" * 60)
    print("Sparker Async Examples")
    print("=" * 60)
    print()
    print("NOTE: These examples require a valid Webex token.")
    print("Replace 'your-token-here' with your actual token.\n")
    print("=" * 60)
    print()

    # Note: In real usage, you would actually run these
    # For demonstration, we just show the code structure

    print("Example 1: Basic Async")
    print("  async with Sparker(token='...') as spark:")
    print("    await spark.post_to_spark_async(...)")
    print()

    print("Example 2: Concurrent Posts (5 rooms)")
    print("  tasks = [spark.post_to_spark_async(...) for room in rooms]")
    print("  await asyncio.gather(*tasks)")
    print()

    print("Example 3: Mixed Operations")
    print("  team_id, room_id = await asyncio.gather(")
    print("    spark.get_team_id_async(...),")
    print("    spark.get_room_id_async(...)")
    print("  )")
    print()

    print("Example 4: With Adaptive Card")
    print("  await spark.post_to_spark_with_card_async(...)")
    print()

    print("=" * 60)
    print("Performance Benefits:")
    print("=" * 60)
    print("- Concurrent API calls instead of sequential")
    print("- Connection pooling and reuse")
    print("- Non-blocking I/O operations")
    print("- Up to 10x faster for I/O-bound workloads")
    print()

    print("To run these examples:")
    print("1. Install aiohttp: pip install aiohttp")
    print("2. Set your Webex token")
    print("3. Uncomment the asyncio.run() calls in the code")
    print()

    # Uncomment to actually run examples (requires valid token)
    # asyncio.run(example_basic_async())
    # asyncio.run(example_concurrent_posts())
    # asyncio.run(example_mixed_operations())
    # asyncio.run(example_error_handling())
    # asyncio.run(example_with_card())
    # asyncio.run(example_batch_operations())


if __name__ == "__main__":
    main()

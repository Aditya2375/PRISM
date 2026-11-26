from kig.detector import AnomalyDetector

detector = AnomalyDetector(burst_threshold=5, window_seconds=10)

# First 4 fetches
for i in range(4):
    alerts = detector.observe({
        'ts': f'2024-01-01T00:00:{i*2}:00Z',
        'actor': 'alice',
        'action': 'key_fetch',
        'key_id': 'key1',
        'result': 'success',
    })
    print(f'After fetch {i+1}: alerts={alerts}, fetch_timestamps_len={len(detector._fetch_timestamps["alice"])}')

# 5th fetch
alerts = detector.observe({
    'ts': '2024-01-01T00:00:08Z',
    'actor': 'alice',
    'action': 'key_fetch',
    'key_id': 'key1',
    'result': 'success',
})
print(f'After fetch 5: alerts={alerts}, fetch_timestamps_len={len(detector._fetch_timestamps["alice"])}')
print(f'metrics: {detector.metrics()}')
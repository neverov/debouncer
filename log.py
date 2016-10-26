import logging

_handler = logging.StreamHandler()
_handler.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s'))
_logger = logging.getLogger(__name__)
_logger.addHandler(_handler)
_logger.setLevel(logging.INFO)

def build_logger(name):
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s'))
    logger = logging.getLogger(name)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger

def logfn(logger):
    if logger is None:
        logger = build_logger(func.__name__)
    def log_fn(func):
        def wrapper(*args, **kwargs):
            logger.info('START FN={} ARGS={} KWARGS={}'.format(func.__name__, args, kwargs))
            result = func(*args, **kwargs)
            logger.info('END FN={} ARGS={} KWARGS={}'.format(func.__name__, args, kwargs))
            return result
        return wrapper
    return log_fn
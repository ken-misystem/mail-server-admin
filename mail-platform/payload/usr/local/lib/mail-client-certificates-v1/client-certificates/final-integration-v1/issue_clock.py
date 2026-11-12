"""Post-signing wall time, separate from reservation time and monotonic expiry."""
def fresh_time(clock,started):
    now=clock()
    if type(now)is not int or type(started)is not int or not 0<=now-started<=220:raise ValueError('issuance_wall_clock_discontinuity')
    return now
class CurrentInspector:
    def __init__(self,delegate,clock):self.delegate,self.clock=delegate,clock
    def inspect(self,region,device,issuer,serial,started):
        return self.delegate.inspect(region,device,issuer,serial,fresh_time(self.clock,started))
